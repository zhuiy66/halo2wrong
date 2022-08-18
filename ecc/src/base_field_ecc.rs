use super::{make_mul_aux, AssignedPoint, MulAux, Point};
use crate::{halo2, maingate, EccInstructions};
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::plonk::Error;
use integer::halo2::circuit::Value;
use integer::maingate::{AssignedValue, RegionCtx};
use integer::{IntegerInstructions, Range};
use maingate::AssignedCondition;
use std::{collections::BTreeMap, fmt::Debug};

mod add;
mod mul;

pub trait NativeInstructions<F: FieldExt> =
    IntegerInstructions<F, F, MainGate = Self, Integer = F, AssignedInteger = AssignedValue<F>>;

/// Constaints elliptic curve operations such as assigment, addition and
/// multiplication. Elliptic curves constrained here is the same curve in the
/// proof system where base field is the non native field.
#[derive(Clone, Debug)]
pub struct BaseFieldEccChip<C, BaseFieldChip>
where
    C: CurveAffine,
    BaseFieldChip: IntegerInstructions<C::Base, C::ScalarExt>,
    BaseFieldChip::MainGate: NativeInstructions<C::Scalar>,
{
    /// `MainGate` that also serves as `ScalarFieldChip`
    main_gate: BaseFieldChip::MainGate,
    /// Chip for EC base field operations
    base_field_chip: BaseFieldChip,
    /// Auxiliary point for optimized multiplication algorithm
    aux_generator: Option<(AssignedPoint<BaseFieldChip::AssignedInteger>, Value<C>)>,
    /// Auxiliary points for optimized multiplication for each (window_size,
    /// n_pairs) pairs
    aux_registry: BTreeMap<(usize, usize), AssignedPoint<BaseFieldChip::AssignedInteger>>,
}

impl<C, BaseFieldChip> BaseFieldEccChip<C, BaseFieldChip>
where
    C: CurveAffine,
    BaseFieldChip: IntegerInstructions<C::Base, C::ScalarExt>,
    BaseFieldChip::MainGate: NativeInstructions<C::Scalar>,
{
    /// Return `BaseEccChip` from `EccConfig`
    pub fn new(base_field_chip: BaseFieldChip) -> Self {
        Self {
            main_gate: base_field_chip.main_gate().clone(),
            base_field_chip,
            aux_generator: None,
            aux_registry: BTreeMap::new(),
        }
    }

    /// Returns `BaseFieldChip` for the base field of the emulated EC
    pub fn base_field_chip(&self) -> &BaseFieldChip {
        &self.base_field_chip
    }

    /// Returns `MainGate`
    pub fn main_gate(&self) -> &BaseFieldChip::MainGate {
        &self.main_gate
    }

    /// Returns a `Point` (Rns representation) from a point in the emulated EC
    pub fn to_rns_point(&self, point: C) -> Point<BaseFieldChip::Integer> {
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
        self.base_field_chip.integer(C::b())
    }

    /// Auxilary point for optimized multiplication algorithm
    fn get_mul_aux(
        &self,
        window_size: usize,
        number_of_pairs: usize,
    ) -> Result<MulAux<BaseFieldChip::AssignedInteger>, Error> {
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

impl<C, BaseFieldChip> EccInstructions<C, C::Scalar> for BaseFieldEccChip<C, BaseFieldChip>
where
    C: CurveAffine,
    BaseFieldChip: IntegerInstructions<C::Base, C::ScalarExt>,
    BaseFieldChip::MainGate: NativeInstructions<C::Scalar>,
{
    type MainGate = BaseFieldChip::MainGate;
    type BaseFieldChip = BaseFieldChip;
    type ScalarFieldChip = BaseFieldChip::MainGate;
    type AssignedPoint = AssignedPoint<BaseFieldChip::AssignedInteger>;
    type Base = BaseFieldChip::Integer;
    type AssignedBase = BaseFieldChip::AssignedInteger;
    type Scalar = C::Scalar;
    type AssignedScalar = AssignedValue<C::Scalar>;

    fn base_field_chip(&self) -> &Self::BaseFieldChip {
        self.base_field_chip()
    }

    fn scalar_field_chip(&self) -> &Self::ScalarFieldChip {
        self.main_gate()
    }

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: C,
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
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: Value<C>,
    ) -> Result<Self::AssignedPoint, Error> {
        let base_field_chip = self.base_field_chip();

        let point = point.map(|point| self.to_rns_point(point));
        let (x, y) = point
            .map(|point| (point.get_x().clone(), point.get_y().clone()))
            .unzip();

        let x = base_field_chip.assign_integer(ctx, x, Range::Remainder)?;
        let y = base_field_chip.assign_integer(ctx, y, Range::Remainder)?;

        let point = AssignedPoint::new(x, y);
        self.assert_is_on_curve(ctx, &point)?;
        Ok(point)
    }

    fn assign_aux_generator(
        &mut self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        aux_generator: Value<C>,
    ) -> Result<(), Error> {
        let aux_generator_assigned = self.assign_point(ctx, aux_generator)?;
        self.aux_generator = Some((aux_generator_assigned, aux_generator));
        Ok(())
    }

    fn assign_aux(
        &mut self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
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
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: &Self::AssignedPoint,
    ) -> Result<(), Error> {
        let base_field_chip = self.base_field_chip();

        let y_square = &base_field_chip.square(ctx, point.get_y())?;
        let x_square = &base_field_chip.square(ctx, point.get_x())?;
        let x_cube = &base_field_chip.mul(ctx, point.get_x(), x_square)?;
        let x_cube_b = &base_field_chip.add_constant(ctx, x_cube, &self.parameter_b())?;
        base_field_chip.assert_equal(ctx, x_cube_b, y_square)?;
        Ok(())
    }

    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        p0: &Self::AssignedPoint,
        p1: &Self::AssignedPoint,
    ) -> Result<(), Error> {
        let base_field_chip = self.base_field_chip();
        base_field_chip.assert_equal(ctx, p0.get_x(), p1.get_x())?;
        base_field_chip.assert_equal(ctx, p0.get_y(), p1.get_y())
    }

    fn select(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        c: &AssignedCondition<C::Scalar>,
        p1: &Self::AssignedPoint,
        p2: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        let base_field_chip = self.base_field_chip();
        let x = base_field_chip.select(ctx, p1.get_x(), p2.get_x(), c)?;
        let y = base_field_chip.select(ctx, p1.get_y(), p2.get_y(), c)?;
        Ok(AssignedPoint::new(x, y))
    }

    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        c: &AssignedCondition<C::Scalar>,
        p1: &Self::AssignedPoint,
        p2: C,
    ) -> Result<Self::AssignedPoint, Error> {
        let base_field_chip = self.base_field_chip();
        let p2 = self.to_rns_point(p2);
        let x = base_field_chip.select_or_assign(ctx, p1.get_x(), p2.get_x(), c)?;
        let y = base_field_chip.select_or_assign(ctx, p1.get_y(), p2.get_y(), c)?;
        Ok(AssignedPoint::new(x, y))
    }

    fn normalize(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        let base_field_chip = self.base_field_chip();
        let x = base_field_chip.reduce(ctx, point.get_x())?;
        let y = base_field_chip.reduce(ctx, point.get_y())?;
        Ok(AssignedPoint::new(x, y))
    }

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
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
        ctx: &mut RegionCtx<'_, C::Scalar>,
        p: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        // point must be asserted to be in curve and not infinity
        self._double_incomplete(ctx, p)
    }

    fn double_n(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
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
        ctx: &mut RegionCtx<'_, C::Scalar>,
        to_double: &Self::AssignedPoint,
        to_add: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        self._ladder_incomplete(ctx, to_double, to_add)
    }

    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        p: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        let base_field_chip = self.base_field_chip();
        let y_neg = base_field_chip.neg(ctx, p.get_y())?;
        Ok(AssignedPoint::new(p.get_x().clone(), y_neg))
    }

    fn sign(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        p: &Self::AssignedPoint,
    ) -> Result<AssignedCondition<C::Scalar>, Error> {
        self.base_field_chip().sign(ctx, p.get_y())
    }

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: &Self::AssignedPoint,
        scalar: &AssignedValue<C::Scalar>,
        window_size: usize,
    ) -> Result<Self::AssignedPoint, Error> {
        self.mul(ctx, point, scalar, window_size)
    }

    fn mul_batch_1d_horizontal(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        pairs: Vec<(Self::AssignedPoint, AssignedValue<C::Scalar>)>,
        window_size: usize,
    ) -> Result<Self::AssignedPoint, Error> {
        self.mul_batch_1d_horizontal(ctx, pairs, window_size)
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use std::rc::Rc;

    use super::BaseFieldEccChip;
    use crate::curves::bn256::G1Affine as Bn256;
    use crate::curves::pasta::{EpAffine as Pallas, EqAffine as Vesta};
    use crate::halo2;
    use crate::integer::rns::Rns;
    use crate::integer::NUMBER_OF_LOOKUP_LIMBS;
    use crate::maingate;
    use crate::EccInstructions;
    use group::{Curve as _, Group};
    use halo2::arithmetic::{CurveAffine, FieldExt};
    use halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use integer::maingate::RegionCtx;
    use integer::{rns::Integer, IntegerChip};
    use maingate::mock_prover_verify;
    use maingate::{
        MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
    };
    use paste::paste;
    use rand_core::OsRng;

    const NUMBER_OF_LIMBS: usize = 4;
    const BIT_LEN_LIMB: usize = 68;

    fn rns<C: CurveAffine>() -> Rns<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        Rns::construct()
    }

    fn setup<C: CurveAffine>(
        k_override: u32,
    ) -> (Rns<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, u32) {
        let rns = rns::<C>();
        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
        let mut k: u32 = (bit_len_lookup + 1) as u32;
        if k_override != 0 {
            k = k_override;
        }
        (rns, k)
    }

    #[derive(Clone, Debug)]
    struct TestCircuitConfig<C: CurveAffine> {
        main_gate_config: MainGateConfig,
        range_config: RangeConfig,
        rns: Rc<Rns<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    }

    impl<C: CurveAffine> TestCircuitConfig<C> {
        fn main_gate(&self) -> MainGate<C::Scalar> {
            MainGate::new(self.main_gate_config.clone())
        }

        #[allow(clippy::type_complexity)]
        fn base_field_chip(
            &self,
        ) -> IntegerChip<
            C::Base,
            C::Scalar,
            MainGate<C::Scalar>,
            RangeChip<C::Scalar>,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
        > {
            IntegerChip::new(
                self.main_gate(),
                RangeChip::new(self.range_config.clone()),
                self.rns.clone(),
            )
        }
    }

    impl<C: CurveAffine> TestCircuitConfig<C> {
        fn new(meta: &mut ConstraintSystem<C::Scalar>) -> Self {
            let rns = Rns::construct();

            let main_gate_config = MainGate::<C::Scalar>::configure(meta);
            let overflow_bit_lens = rns.overflow_lengths();
            let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

            let range_config = RangeChip::<C::Scalar>::configure(
                meta,
                &main_gate_config,
                composition_bit_lens,
                overflow_bit_lens,
            );

            TestCircuitConfig {
                main_gate_config,
                range_config,
                rns: Rc::new(rns),
            }
        }

        fn config_range<N: FieldExt>(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
            let range_chip = RangeChip::<N>::new(self.range_config.clone());
            range_chip.load_table(layouter)?;

            Ok(())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct TestEccAddition<C> {
        _marker: PhantomData<C>,
    }

    impl<C: CurveAffine> Circuit<C::Scalar> for TestEccAddition<C> {
        type Config = TestCircuitConfig<C>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
            TestCircuitConfig::new(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<C::Scalar>,
        ) -> Result<(), Error> {
            let ecc_chip = BaseFieldEccChip::<C, _>::new(config.base_field_chip());
            layouter.assign_region(
                || "region 0",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let a = C::CurveExt::random(OsRng);
                    let b = C::CurveExt::random(OsRng);

                    let c = a + b;
                    let a = &ecc_chip.assign_point(ctx, Value::known(a.into()))?;
                    let b = &ecc_chip.assign_point(ctx, Value::known(b.into()))?;
                    let c_0 = &ecc_chip.assign_point(ctx, Value::known(c.into()))?;
                    let c_1 = &ecc_chip.add(ctx, a, b)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    let c_1 = &ecc_chip.add(ctx, a, b)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    // test doubling

                    let a = C::CurveExt::random(OsRng);
                    let c = a + a;

                    let a = &ecc_chip.assign_point(ctx, Value::known(a.into()))?;
                    let c_0 = &ecc_chip.assign_point(ctx, Value::known(c.into()))?;
                    let c_1 = &ecc_chip.double(ctx, a)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    // test ladder

                    let a = C::CurveExt::random(OsRng);
                    let b = C::CurveExt::random(OsRng);
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
    fn test_base_field_ecc_addition_circuit() {
        fn run<C: CurveAffine>() {
            let circuit = TestEccAddition::<C>::default();
            let instance = vec![vec![]];
            assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
        }
        run::<Bn256>();
        run::<Pallas>();
        run::<Vesta>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccPublicInput<C: CurveAffine> {
        a: Value<C>,
        b: Value<C>,
    }

    impl<C: CurveAffine> Circuit<C::Scalar> for TestEccPublicInput<C> {
        type Config = TestCircuitConfig<C>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
            TestCircuitConfig::new(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<C::Scalar>,
        ) -> Result<(), Error> {
            let main_gate = config.main_gate();
            let ecc_chip = BaseFieldEccChip::<C, _>::new(config.base_field_chip());

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
                main_gate.expose_public(layouter.namespace(|| "coords"), limb.into(), offset)?;
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
                main_gate.expose_public(layouter.namespace(|| "coords"), limb.into(), offset)?;
            }

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_base_field_ecc_public_input() {
        fn run<C: CurveAffine>() {
            let (rns, _) = setup::<C>(20);
            let rns = Rc::new(rns);

            let a = <C as CurveAffine>::CurveExt::random(OsRng).to_affine();
            let b = <C as CurveAffine>::CurveExt::random(OsRng).to_affine();

            let c0: C = (a + b).into();
            let c1: C = (a + a).into();
            let public_data = [c0, c1]
                .into_iter()
                .flat_map(|point| {
                    let coords = point.coordinates().unwrap();
                    [*coords.x(), *coords.y()]
                })
                .flat_map(|e| Integer::from_fe(e, Rc::clone(&rns)).limbs())
                .collect::<Vec<_>>();

            let circuit = TestEccPublicInput {
                a: Value::known(a),
                b: Value::known(b),
            };
            let instance = vec![public_data];
            assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
        }

        run::<Bn256>();
        run::<Pallas>();
        run::<Vesta>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccMul<C: CurveAffine> {
        window_size: usize,
        aux_generator: C,
    }

    impl<C: CurveAffine> Circuit<C::Scalar> for TestEccMul<C> {
        type Config = TestCircuitConfig<C>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
            TestCircuitConfig::new(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<C::Scalar>,
        ) -> Result<(), Error> {
            let mut ecc_chip = BaseFieldEccChip::<C, _>::new(config.base_field_chip());
            let main_gate = MainGate::<C::Scalar>::new(config.main_gate_config.clone());

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

            layouter.assign_region(
                || "region 0",
                |region| {
                    use group::ff::Field;
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let base = C::CurveExt::random(OsRng);
                    let s = C::Scalar::random(OsRng);
                    let result = base * s;

                    let base = ecc_chip.assign_point(ctx, Value::known(base.into()))?;
                    let s = main_gate.assign_value(ctx, Value::known(s))?;
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
    fn test_base_field_ecc_mul_circuit() {
        fn run<C: CurveAffine>() {
            for window_size in 1..5 {
                let aux_generator = <C as CurveAffine>::CurveExt::random(OsRng).to_affine();

                let circuit = TestEccMul {
                    aux_generator,
                    window_size,
                };
                let instance = vec![vec![]];
                assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
            }
        }
        run::<Bn256>();
        run::<Pallas>();
        run::<Vesta>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccBatchMul<C: CurveAffine> {
        window_size: usize,
        number_of_pairs: usize,
        aux_generator: C,
    }

    impl<C: CurveAffine> Circuit<C::Scalar> for TestEccBatchMul<C> {
        type Config = TestCircuitConfig<C>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
            TestCircuitConfig::new(meta)
        }

        #[allow(clippy::type_complexity)]
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<C::Scalar>,
        ) -> Result<(), Error> {
            let mut ecc_chip = BaseFieldEccChip::<C, _>::new(config.base_field_chip());
            let main_gate = MainGate::<C::Scalar>::new(config.main_gate_config.clone());

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

            layouter.assign_region(
                || "region 0",
                |region| {
                    use group::ff::Field;
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let mut acc = C::CurveExt::identity();
                    let pairs = (0..self.number_of_pairs)
                        .map(|_| {
                            let base = C::CurveExt::random(OsRng);
                            let s = C::Scalar::random(OsRng);
                            acc += base * s;
                            let base = ecc_chip.assign_point(ctx, Value::known(base.into()))?;
                            let s = main_gate.assign_value(ctx, Value::known(s))?;
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

    macro_rules! test_base_field_ecc_mul_batch_circuit {
        ($C:ty) => {
            paste! {
                #[test]
                fn [<test_base_field_ecc_mul_batch_circuit_ $C:lower>]() {
                    for number_of_pairs in 5..7 {
                        for window_size in 1..3 {
                            let aux_generator = <$C as CurveAffine>::CurveExt::random(OsRng).to_affine();

                            let circuit = TestEccBatchMul {
                                aux_generator,
                                window_size,
                                number_of_pairs,
                            };
                            let instance = vec![vec![]];
                            assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
                        }
                    }
                }
            }
        };
    }

    test_base_field_ecc_mul_batch_circuit!(Bn256);
    test_base_field_ecc_mul_batch_circuit!(Pallas);
    test_base_field_ecc_mul_batch_circuit!(Vesta);
}
