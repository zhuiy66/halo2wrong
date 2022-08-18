use super::{make_mul_aux, AssignedPoint, MulAux, Point};
use crate::integer::{IntegerInstructions, Range};
use crate::maingate;
use crate::{halo2, EccInstructions};
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Value;
use halo2::plonk::Error;
use integer::maingate::{MainGateInstructions, RegionCtx};
use maingate::AssignedCondition;
use std::collections::BTreeMap;

mod add;
mod mul;

/// Constaints elliptic curve operations such as assigment, addition and
/// multiplication
#[derive(Clone, Debug)]
#[allow(clippy::type_complexity)]
pub struct GeneralEccChip<Emulated, N, MainGate, BaseFieldChip, ScalarFieldChip>
where
    Emulated: CurveAffine,
    N: FieldExt,
    MainGate: MainGateInstructions<N>,
    BaseFieldChip: IntegerInstructions<Emulated::Base, N>,
    ScalarFieldChip: IntegerInstructions<Emulated::Scalar, N>,
{
    /// `MainGate` shared among all the other chips
    main_gate: MainGate,
    /// `IntegerChip` for the base field of the EC
    base_field_chip: BaseFieldChip,
    /// `IntegerChip` for the scalar field of the EC
    scalar_field_chip: ScalarFieldChip,
    /// Auxiliary point for optimized multiplication algorithm
    aux_generator: Option<(
        AssignedPoint<BaseFieldChip::AssignedInteger>,
        Value<Emulated>,
    )>,
    /// Auxiliary points for optimized multiplication for each (window_size,
    /// n_pairs) pairs
    aux_registry: BTreeMap<(usize, usize), AssignedPoint<BaseFieldChip::AssignedInteger>>,
}

impl<Emulated, N, MainGate, BaseFieldChip, ScalarFieldChip>
    GeneralEccChip<Emulated, N, MainGate, BaseFieldChip, ScalarFieldChip>
where
    Emulated: CurveAffine,
    N: FieldExt,
    MainGate: MainGateInstructions<N>,
    BaseFieldChip: IntegerInstructions<Emulated::Base, N>,
    ScalarFieldChip: IntegerInstructions<Emulated::Scalar, N>,
{
    /// Return `GeneralEccChip` from `EccConfig`
    pub fn new(
        main_gate: MainGate,
        base_field_chip: BaseFieldChip,
        scalar_field_chip: ScalarFieldChip,
    ) -> Self {
        Self {
            main_gate,
            base_field_chip,
            scalar_field_chip,
            aux_generator: None,
            aux_registry: BTreeMap::new(),
        }
    }

    /// Assign Rns base for chip
    pub fn new_unassigned_base(&self, e: Value<Emulated::Base>) -> Value<BaseFieldChip::Integer> {
        e.map(|e| self.base_field_chip.integer(e))
    }

    /// Assign Rns Scalar for chip
    pub fn new_unassigned_scalar(
        &self,
        e: Value<Emulated::Scalar>,
    ) -> Value<ScalarFieldChip::Integer> {
        e.map(|e| self.scalar_field_chip.integer(e))
    }

    /// Return `IntegerChip` for the base field of the EC
    pub fn base_field_chip(&self) -> &BaseFieldChip {
        &self.base_field_chip
    }

    /// Return `IntegerChip` for the scalar field of the EC
    pub fn scalar_field_chip(&self) -> &ScalarFieldChip {
        &self.scalar_field_chip
    }

    /// Return `Maingate` of the `GeneralEccChip`
    pub fn main_gate(&self) -> &MainGate {
        &self.main_gate
    }

    /// Returns a `Point` (Rns representation) from a point in the emulated EC
    pub fn to_rns_point(&self, point: Emulated) -> Point<BaseFieldChip::Integer> {
        let coords = point.coordinates();
        // disallow point of infinity
        // it will not pass assing point enforcement
        let coords = coords.unwrap();

        let x = self.base_field_chip.integer(*coords.x());
        let y = self.base_field_chip.integer(*coords.y());
        Point::new(x, y)
    }

    /// Returns emulated EC constant $b$
    fn parameter_b(&self) -> BaseFieldChip::Integer {
        self.base_field_chip.integer(Emulated::b())
    }

    /// Auxilary point for optimized multiplication algorithm
    fn get_mul_aux(
        &self,
        window_size: usize,
        number_of_pairs: usize,
    ) -> Result<MulAux<BaseFieldChip::AssignedInteger>, Error> {
        // Gets chips' aux generator
        let to_add = match self.aux_generator.clone() {
            Some((assigned, _)) => Ok(assigned),
            None => Err(Error::Synthesis),
        }?;
        let to_sub = match self.aux_registry.get(&(window_size, number_of_pairs)) {
            Some(aux) => Ok(aux.clone()),
            None => Err(Error::Synthesis),
        }?;
        // to_add the equivalent of AuxInit and to_sub AuxFin
        // see https://hackmd.io/ncuKqRXzR-Cw-Au2fGzsMg?view
        Ok(MulAux::new(to_add, to_sub))
    }
}

impl<Emulated, N, MainGate, BaseFieldChip, ScalarFieldChip> EccInstructions<Emulated, N>
    for GeneralEccChip<Emulated, N, MainGate, BaseFieldChip, ScalarFieldChip>
where
    Emulated: CurveAffine,
    N: FieldExt,
    MainGate: MainGateInstructions<N>,
    BaseFieldChip: IntegerInstructions<Emulated::Base, N>,
    ScalarFieldChip: IntegerInstructions<Emulated::Scalar, N, MainGate = BaseFieldChip::MainGate>,
{
    type MainGate = BaseFieldChip::MainGate;
    type BaseFieldChip = BaseFieldChip;
    type ScalarFieldChip = ScalarFieldChip;
    type AssignedPoint = AssignedPoint<BaseFieldChip::AssignedInteger>;
    type Base = BaseFieldChip::Integer;
    type AssignedBase = BaseFieldChip::AssignedInteger;
    type Scalar = ScalarFieldChip::Integer;
    type AssignedScalar = ScalarFieldChip::AssignedInteger;

    fn base_field_chip(&self) -> &Self::BaseFieldChip {
        self.base_field_chip()
    }

    fn scalar_field_chip(&self) -> &Self::ScalarFieldChip {
        self.scalar_field_chip()
    }

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: Emulated,
    ) -> Result<Self::AssignedPoint, Error> {
        let coords = point.coordinates();
        // disallow point of infinity
        let coords = coords.unwrap();
        let base_field_chip = self.base_field_chip();
        let x = base_field_chip.assign_constant(ctx, *coords.x())?;
        let y = base_field_chip.assign_constant(ctx, *coords.y())?;

        Ok(AssignedPoint::new(x, y))
    }

    fn assign_point(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: Value<Emulated>,
    ) -> Result<Self::AssignedPoint, Error> {
        let integer_chip = self.base_field_chip();

        let point = point.map(|point| self.to_rns_point(point));
        let (x, y) = point
            .map(|point| (point.get_x().clone(), point.get_y().clone()))
            .unzip();

        let x = integer_chip.assign_integer(ctx, x, Range::Remainder)?;
        let y = integer_chip.assign_integer(ctx, y, Range::Remainder)?;

        let point = AssignedPoint::new(x, y);
        self.assert_is_on_curve(ctx, &point)?;
        Ok(point)
    }

    fn assign_aux_generator(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        aux_generator: Value<Emulated>,
    ) -> Result<(), Error> {
        let aux_generator_assigned = self.assign_point(ctx, aux_generator)?;
        self.aux_generator = Some((aux_generator_assigned, aux_generator));
        Ok(())
    }

    fn assign_aux(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        window_size: usize,
        number_of_pairs: usize,
    ) -> Result<(), Error> {
        match self.aux_generator {
            Some((_, point)) => {
                let aux = point.map(|point| make_mul_aux(point, window_size, number_of_pairs));
                let aux = self.assign_point(ctx, aux)?;
                self.aux_registry
                    .insert((window_size, number_of_pairs), aux);
                Ok(())
            }
            // aux generator is not assigned yet
            None => Err(Error::Synthesis),
        }
    }

    fn assert_is_on_curve(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: &Self::AssignedPoint,
    ) -> Result<(), Error> {
        let integer_chip = self.base_field_chip();

        let y_square = &integer_chip.square(ctx, point.get_y())?;
        let x_square = &integer_chip.square(ctx, point.get_x())?;
        let x_cube = &integer_chip.mul(ctx, point.get_x(), x_square)?;
        let x_cube_b = &integer_chip.add_constant(ctx, x_cube, &self.parameter_b())?;
        integer_chip.assert_equal(ctx, x_cube_b, y_square)?;
        Ok(())
    }

    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p0: &Self::AssignedPoint,
        p1: &Self::AssignedPoint,
    ) -> Result<(), Error> {
        let integer_chip = self.base_field_chip();
        integer_chip.assert_equal(ctx, p0.get_x(), p1.get_x())?;
        integer_chip.assert_equal(ctx, p0.get_y(), p1.get_y())
    }

    fn select(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        c: &AssignedCondition<N>,
        p1: &Self::AssignedPoint,
        p2: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        let integer_chip = self.base_field_chip();
        let x = integer_chip.select(ctx, p1.get_x(), p2.get_x(), c)?;
        let y = integer_chip.select(ctx, p1.get_y(), p2.get_y(), c)?;
        Ok(AssignedPoint::new(x, y))
    }

    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        c: &AssignedCondition<N>,
        p1: &Self::AssignedPoint,
        p2: Emulated,
    ) -> Result<Self::AssignedPoint, Error> {
        let integer_chip = self.base_field_chip();
        let p2 = self.to_rns_point(p2);
        let x = integer_chip.select_or_assign(ctx, p1.get_x(), p2.get_x(), c)?;
        let y = integer_chip.select_or_assign(ctx, p1.get_y(), p2.get_y(), c)?;
        Ok(AssignedPoint::new(x, y))
    }

    fn normalize(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        let integer_chip = self.base_field_chip();
        let x = integer_chip.reduce(ctx, point.get_x())?;
        let y = integer_chip.reduce(ctx, point.get_y())?;
        Ok(AssignedPoint::new(x, y))
    }

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p0: &Self::AssignedPoint,
        p1: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        // guarantees that p0 != p1 or p0 != p1
        // so that we can use unsafe addition formula which assumes operands are not
        // equal addition to that we strictly disallow addition result to be
        // point of infinity
        self.base_field_chip()
            .assert_not_equal(ctx, p0.get_x(), p1.get_x())?;

        self._add_incomplete_unsafe(ctx, p0, p1)
    }

    fn double(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        // point must be asserted to be in curve and not infinity
        self._double_incomplete(ctx, p)
    }

    fn double_n(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p: &Self::AssignedPoint,
        logn: usize,
    ) -> Result<Self::AssignedPoint, Error> {
        let mut acc = p.clone();
        for _ in 0..logn {
            acc = self._double_incomplete(ctx, &acc)?;
        }
        Ok(acc)
    }

    fn ladder(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        to_double: &Self::AssignedPoint,
        to_add: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        self._ladder_incomplete(ctx, to_double, to_add)
    }

    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        let integer_chip = self.base_field_chip();
        let y_neg = integer_chip.neg(ctx, p.get_y())?;
        Ok(AssignedPoint::new(p.get_x().clone(), y_neg))
    }

    fn sign(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p: &Self::AssignedPoint,
    ) -> Result<AssignedCondition<N>, Error> {
        self.base_field_chip().sign(ctx, p.get_y())
    }

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: &Self::AssignedPoint,
        scalar: &ScalarFieldChip::AssignedInteger,
        window_size: usize,
    ) -> Result<Self::AssignedPoint, Error> {
        self.mul(ctx, point, scalar, window_size)
    }

    fn mul_batch_1d_horizontal(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        pairs: Vec<(Self::AssignedPoint, ScalarFieldChip::AssignedInteger)>,
        window_size: usize,
    ) -> Result<Self::AssignedPoint, Error> {
        self.mul_batch_1d_horizontal(ctx, pairs, window_size)
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use std::rc::Rc;

    use super::GeneralEccChip;
    use crate::integer::rns::Rns;
    use crate::integer::IntegerInstructions;
    use crate::integer::NUMBER_OF_LOOKUP_LIMBS;
    use crate::maingate;
    use crate::{halo2, EccInstructions};
    use group::{prime::PrimeCurveAffine, Curve as _, Group};
    use halo2::arithmetic::{CurveAffine, FieldExt};
    use halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use integer::maingate::MainGateInstructions;
    use integer::rns::Integer;
    use integer::IntegerChip;
    use integer::Range;
    use maingate::mock_prover_verify;
    use maingate::{
        MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
    };
    use paste::paste;
    use rand_core::OsRng;

    use crate::curves::bn256::{Fr as BnScalar, G1Affine as Bn256};
    use crate::curves::pasta::{
        EpAffine as Pallas, EqAffine as Vesta, Fp as PastaFp, Fq as PastaFq,
    };
    use crate::curves::secp256k1::Secp256k1Affine as Secp256k1;

    const NUMBER_OF_LIMBS: usize = 4;
    const BIT_LEN_LIMB: usize = 68;

    #[allow(clippy::type_complexity)]
    fn setup<
        C: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    >(
        k_override: u32,
    ) -> (
        Rns<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        Rns<C::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        u32,
    ) {
        let (rns_base, rns_scalar) = (Rns::construct(), Rns::construct());
        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
        let mut k: u32 = (bit_len_lookup + 1) as u32;
        if k_override != 0 {
            k = k_override;
        }
        (rns_base, rns_scalar, k)
    }

    #[derive(Clone, Debug)]
    struct TestCircuitConfig<
        C: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        main_gate_config: MainGateConfig,
        range_config: RangeConfig,
        rns_base: Rc<Rns<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
        rns_scalar: Rc<Rns<C::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    }

    impl<C: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
        TestCircuitConfig<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        fn main_gate(&self) -> MainGate<N> {
            MainGate::new(self.main_gate_config.clone())
        }

        fn base_field_chip(
            &self,
        ) -> IntegerChip<C::Base, N, MainGate<N>, RangeChip<N>, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
        {
            IntegerChip::new(
                self.main_gate(),
                RangeChip::new(self.range_config.clone()),
                self.rns_base.clone(),
            )
        }

        fn scalar_field_chip(
            &self,
        ) -> IntegerChip<C::Scalar, N, MainGate<N>, RangeChip<N>, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
        {
            IntegerChip::new(
                self.main_gate(),
                RangeChip::new(self.range_config.clone()),
                self.rns_scalar.clone(),
            )
        }
    }

    impl<C: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
        TestCircuitConfig<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        fn new(meta: &mut ConstraintSystem<N>) -> Self {
            let (rns_base, rns_scalar) = (Rns::construct(), Rns::construct());

            let main_gate_config = MainGate::<N>::configure(meta);
            let mut overflow_bit_lens: Vec<usize> = vec![];
            overflow_bit_lens.extend(rns_base.overflow_lengths());
            overflow_bit_lens.extend(rns_scalar.overflow_lengths());
            let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

            let range_config = RangeChip::<N>::configure(
                meta,
                &main_gate_config,
                composition_bit_lens,
                overflow_bit_lens,
            );

            TestCircuitConfig {
                main_gate_config,
                range_config,
                rns_base: Rc::new(rns_base),
                rns_scalar: Rc::new(rns_scalar),
            }
        }

        fn config_range(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
            let range_chip = RangeChip::<N>::new(self.range_config.clone());
            range_chip.load_table(layouter)?;

            Ok(())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct TestEccAddition<
        C: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        _marker: PhantomData<(C, N)>,
    }

    impl<C: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
        Circuit<N> for TestEccAddition<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let ecc_chip = GeneralEccChip::<C, N, _, _, _>::new(
                config.main_gate(),
                config.base_field_chip(),
                config.scalar_field_chip(),
            );
            layouter.assign_region(
                || "region 0",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let a = C::Curve::random(OsRng);
                    let b = C::Curve::random(OsRng);

                    let c = a + b;
                    let a = &ecc_chip.assign_point(ctx, Value::known(a.into()))?;
                    let b = &ecc_chip.assign_point(ctx, Value::known(b.into()))?;
                    let c_0 = &ecc_chip.assign_point(ctx, Value::known(c.into()))?;
                    let c_1 = &ecc_chip.add(ctx, a, b)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    let c_1 = &ecc_chip.add(ctx, a, b)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    // test doubling

                    let a = C::Curve::random(OsRng);
                    let c = a + a;

                    let a = &ecc_chip.assign_point(ctx, Value::known(a.into()))?;
                    let c_0 = &ecc_chip.assign_point(ctx, Value::known(c.into()))?;
                    let c_1 = &ecc_chip.double(ctx, a)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    // test ladder

                    let a = C::Curve::random(OsRng);
                    let b = C::Curve::random(OsRng);
                    let c = a + b + a;

                    let a = &ecc_chip.assign_point(ctx, Value::known(a.into()))?;
                    let b = &ecc_chip.assign_point(ctx, Value::known(b.into()))?;
                    let c_0 = &ecc_chip.assign_point(ctx, Value::known(c.into()))?;
                    let c_1 = &ecc_chip.ladder(ctx, a, b)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_general_ecc_addition_circuit() {
        fn run<
            C: CurveAffine,
            N: FieldExt,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        >() {
            let circuit = TestEccAddition::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::default();
            let instance = vec![vec![]];
            assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
        }

        run::<Pallas, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Vesta, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Bn256, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Secp256k1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccPublicInput<
        C: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        a: Value<C>,
        b: Value<C>,
        _marker: PhantomData<N>,
    }

    impl<C: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
        Circuit<N> for TestEccPublicInput<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let ecc_chip = GeneralEccChip::<C, N, _, _, _>::new(
                config.main_gate(),
                config.base_field_chip(),
                config.scalar_field_chip(),
            );

            let sum = layouter.assign_region(
                || "region 0",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let a = self.a;
                    let b = self.b;
                    let a = ecc_chip.assign_point(ctx, a)?;
                    let b = ecc_chip.assign_point(ctx, b)?;
                    let c = ecc_chip.add(ctx, &a, &b)?;
                    ecc_chip.normalize(ctx, &c)
                },
            )?;
            for (limb, offset) in [sum.get_x(), sum.get_y()]
                .iter()
                .flat_map(|integer| integer.limbs())
                .zip(0..)
            {
                ecc_chip.main_gate().expose_public(
                    layouter.namespace(|| "sum"),
                    limb.into(),
                    offset,
                )?;
            }

            let sum = layouter.assign_region(
                || "region 1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let a = self.a;
                    let a = ecc_chip.assign_point(ctx, a)?;
                    let c = ecc_chip.double(ctx, &a)?;
                    ecc_chip.normalize(ctx, &c)
                },
            )?;
            for (limb, offset) in [sum.get_x(), sum.get_y()]
                .iter()
                .flat_map(|integer| integer.limbs())
                .zip(8..)
            {
                ecc_chip.main_gate().expose_public(
                    layouter.namespace(|| "sum"),
                    limb.into(),
                    offset,
                )?;
            }

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_general_ecc_public_input() {
        fn run<
            C: CurveAffine,
            N: FieldExt,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        >() {
            let (rns_base, _, _) = setup::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>(0);
            let rns_base = Rc::new(rns_base);

            let a = C::Curve::random(OsRng).to_affine();
            let b = C::Curve::random(OsRng).to_affine();

            let c0: C = (a + b).into();
            let c1: C = (a + a).into();
            let public_data = [c0, c1]
                .into_iter()
                .flat_map(|point| {
                    let coords = point.coordinates().unwrap();
                    [*coords.x(), *coords.y()]
                })
                .flat_map(|e| Integer::from_fe(e, Rc::clone(&rns_base)).limbs())
                .collect::<Vec<_>>();
            let circuit = TestEccPublicInput::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
                a: Value::known(a),
                b: Value::known(b),
                ..Default::default()
            };
            let instance = vec![public_data];
            assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
        }

        run::<Pallas, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Vesta, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Bn256, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Secp256k1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccMul<
        C: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        window_size: usize,
        aux_generator: C,
        _marker: PhantomData<N>,
    }

    impl<C: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
        Circuit<N> for TestEccMul<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let mut ecc_chip = GeneralEccChip::<C, N, _, _, _>::new(
                config.main_gate(),
                config.base_field_chip(),
                config.scalar_field_chip(),
            );

            layouter.assign_region(
                || "assign aux values",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
                    ecc_chip.assign_aux(ctx, self.window_size, 1)?;
                    ecc_chip.get_mul_aux(self.window_size, 1)?;
                    Ok(())
                },
            )?;

            let scalar_chip = ecc_chip.scalar_field_chip();

            layouter.assign_region(
                || "region mul",
                |region| {
                    use group::ff::Field;
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let base = C::Curve::random(OsRng);
                    let s = C::Scalar::random(OsRng);
                    let result = base * s;

                    let s = ecc_chip.scalar_field_chip().integer(s);
                    let base = ecc_chip.assign_point(ctx, Value::known(base.into()))?;
                    let s = scalar_chip.assign_integer(ctx, Value::known(s), Range::Remainder)?;
                    let result_0 = ecc_chip.assign_point(ctx, Value::known(result.into()))?;

                    let result_1 = ecc_chip.mul(ctx, &base, &s, self.window_size)?;
                    ecc_chip.assert_equal(ctx, &result_0, &result_1)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_general_ecc_mul_circuit() {
        fn run<
            C: CurveAffine,
            N: FieldExt,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        >() {
            for window_size in 1..5 {
                let aux_generator = C::Curve::random(OsRng).to_affine();

                let circuit = TestEccMul::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
                    aux_generator,
                    window_size,
                    ..Default::default()
                };
                let instance = vec![vec![]];
                assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
            }
        }

        run::<Pallas, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Vesta, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Bn256, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Secp256k1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccBatchMul<
        C: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        window_size: usize,
        aux_generator: C,
        number_of_pairs: usize,
        _marker: PhantomData<N>,
    }

    impl<C: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
        Circuit<N> for TestEccBatchMul<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new(meta)
        }

        #[allow(clippy::type_complexity)]
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let mut ecc_chip = GeneralEccChip::<C, N, _, _, _>::new(
                config.main_gate(),
                config.base_field_chip(),
                config.scalar_field_chip(),
            );

            layouter.assign_region(
                || "assign aux values",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
                    ecc_chip.assign_aux(ctx, self.window_size, self.number_of_pairs)?;
                    ecc_chip.get_mul_aux(self.window_size, self.number_of_pairs)?;
                    Ok(())
                },
            )?;

            let scalar_chip = ecc_chip.scalar_field_chip();

            layouter.assign_region(
                || "region mul",
                |region| {
                    use group::ff::Field;
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let mut acc = C::Curve::identity();
                    let pairs = (0..self.number_of_pairs)
                        .map(|_| {
                            let base = C::Curve::random(OsRng);
                            let s = C::Scalar::random(OsRng);
                            acc += base * s;
                            let s = ecc_chip.scalar_field_chip().integer(s);
                            let base = ecc_chip.assign_point(ctx, Value::known(base.into()))?;
                            let s = scalar_chip.assign_integer(
                                ctx,
                                Value::known(s),
                                Range::Remainder,
                            )?;
                            Ok((base, s))
                        })
                        .collect::<Result<Vec<_>, Error>>()?;

                    let result_0 = ecc_chip.assign_point(ctx, Value::known(acc.into()))?;
                    let result_1 =
                        ecc_chip.mul_batch_1d_horizontal(ctx, pairs, self.window_size)?;
                    ecc_chip.assert_equal(ctx, &result_0, &result_1)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    macro_rules! test_general_ecc_mul_batch_circuit {
        ($C:ty, $N:ty, $NUMBER_OF_LIMBS:expr, $BIT_LEN_LIMB:expr) => {
            paste! {
                #[test]
                fn [<test_general_ecc_mul_batch_circuit_ $C:lower _ $N:lower>]() {
                    for number_of_pairs in 5..7 {
                        for window_size in 1..3 {
                            let aux_generator = <$C as PrimeCurveAffine>::Curve::random(OsRng).to_affine();

                            let circuit = TestEccBatchMul::<$C, $N, $NUMBER_OF_LIMBS, $BIT_LEN_LIMB> {
                                aux_generator,
                                window_size,
                                number_of_pairs,
                                ..Default::default()
                            };
                            let instance = vec![vec![]];
                            assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
                        }
                    }
                }
            }
        }
    }

    test_general_ecc_mul_batch_circuit!(Pallas, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Pallas, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Pallas, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB);

    test_general_ecc_mul_batch_circuit!(Vesta, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Vesta, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Vesta, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB);

    test_general_ecc_mul_batch_circuit!(Bn256, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Bn256, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Bn256, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB);

    test_general_ecc_mul_batch_circuit!(Secp256k1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Secp256k1, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Secp256k1, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
}
