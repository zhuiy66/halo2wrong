use crate::halo2::arithmetic::{CurveAffine, FieldExt};
use crate::halo2::halo2curves::group::{ff::PrimeField, Curve};
use crate::halo2::plonk::Error;
use crate::integer::maingate::{big_to_fe, AssignedCondition};
use integer::halo2::circuit::Value;
use integer::maingate::{MainGateInstructions, RegionCtx};
use integer::IntegerInstructions;
use num_bigint::BigUint as big_uint;
use num_traits::One;
use std::fmt;
use std::fmt::Debug;

/// Common functionality for elliptic curve operations
pub trait EccInstructions<C: CurveAffine, N: FieldExt>: Clone + Debug {
    /// `MainGateInstructions` shared among all the other chips
    type MainGate: MainGateInstructions<N>;

    /// `IntegerInstructions` used to provide EC base field operations.
    type BaseFieldChip: IntegerInstructions<
        C::Base,
        N,
        MainGate = Self::MainGate,
        Integer = Self::Base,
        AssignedInteger = Self::AssignedBase,
    >;

    /// `IntegerInstructions` used to provide EC scalar field operations.
    type ScalarFieldChip: IntegerInstructions<
        C::Scalar,
        N,
        MainGate = Self::MainGate,
        Integer = Self::Scalar,
        AssignedInteger = Self::AssignedScalar,
    >;

    /// Assigned EC point
    type AssignedPoint: Clone + Debug;

    /// Structure for base field value
    type Base: Clone + Debug;

    /// Assigned base field value
    type AssignedBase: Clone + Debug;

    /// Structure for scalar field value
    type Scalar: Clone + Debug;

    /// Assigned scalar field value
    type AssignedScalar: Clone + Debug;

    /// Returns reference to `EccInstructions::MainGate`
    fn main_gate(&self) -> &Self::MainGate {
        self.base_field_chip().main_gate()
    }

    /// Returns reference to `EccInstructions::BaseFieldChip`
    fn base_field_chip(&self) -> &Self::BaseFieldChip;

    /// Returns reference to `EccInstructions::ScalarFieldChip`
    fn scalar_field_chip(&self) -> &Self::ScalarFieldChip;

    /// Assign constant point
    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: C,
    ) -> Result<Self::AssignedPoint, Error>;

    /// Assign variable point
    fn assign_point(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: Value<C>,
    ) -> Result<Self::AssignedPoint, Error>;

    /// Assigns the auxiliary generator point
    fn assign_aux_generator(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        aux_generator: Value<C>,
    ) -> Result<(), Error>;

    /// Assigns multiplication auxiliary point for a pair of (window_size,
    /// n_pairs)
    fn assign_aux(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        window_size: usize,
        number_of_pairs: usize,
    ) -> Result<(), Error>;

    /// Constraints to ensure `AssignedPoint` is on curve
    fn assert_is_on_curve(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: &Self::AssignedPoint,
    ) -> Result<(), Error>;

    /// Constraints assert two `AssignedPoint`s are equal
    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p0: &Self::AssignedPoint,
        p1: &Self::AssignedPoint,
    ) -> Result<(), Error>;

    /// Selects between 2 `AssignedPoint` determined by an `AssignedCondition`
    fn select(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        c: &AssignedCondition<N>,
        p1: &Self::AssignedPoint,
        p2: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error>;

    /// Selects between an `AssignedPoint` and a point on the EC `Emulated`
    /// determined by an `AssignedCondition`
    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        c: &AssignedCondition<N>,
        p1: &Self::AssignedPoint,
        p2: C,
    ) -> Result<Self::AssignedPoint, Error>;

    /// Normalizes an `AssignedPoint` by reducing each of its coordinates
    fn normalize(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error>;

    /// Adds 2 distinct `AssignedPoints`
    fn add(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p0: &Self::AssignedPoint,
        p1: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error>;

    /// Doubles an `AssignedPoint`
    fn double(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error>;

    /// Given an `AssignedPoint` $P$ computes P * 2^logn
    fn double_n(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p: &Self::AssignedPoint,
        logn: usize,
    ) -> Result<Self::AssignedPoint, Error>;

    /// Wrapper for `_ladder_incomplete`
    /// Given 2 `AssignedPoint` $P$ and $Q$ efficiently computes $2*P + Q$
    fn ladder(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        to_double: &Self::AssignedPoint,
        to_add: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error>;

    /// Returns the negative or inverse of an `AssignedPoint`
    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error>;

    /// Returns sign of the assigned point
    fn sign(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p: &Self::AssignedPoint,
    ) -> Result<AssignedCondition<N>, Error>;

    /// Scalar multiplication of a point in the EC
    /// Performed with the sliding-window algorithm
    fn mul(
        &self,
        region: &mut RegionCtx<'_, N>,
        point: &Self::AssignedPoint,
        scalar: &Self::AssignedScalar,
        window_size: usize,
    ) -> Result<Self::AssignedPoint, Error>;

    /// Computes multi-product
    ///
    /// Given a vector of point, scalar pairs
    /// `[(P_0, e_0), (P_1, e_1), ..., (P_k, e_k)] `
    /// Returns:
    /// `P_0 * e_0 + P_1 * e_1 + ...+ P_k * e_k`
    fn mul_batch_1d_horizontal(
        &self,
        region: &mut RegionCtx<'_, N>,
        pairs: Vec<(Self::AssignedPoint, Self::AssignedScalar)>,
        window_size: usize,
    ) -> Result<Self::AssignedPoint, Error>;
}

/// Represent a Point in affine coordinates
#[derive(Clone, Debug)]
pub struct Point<T: Clone + Debug> {
    pub(crate) x: T,
    pub(crate) y: T,
}

impl<T: Clone + Debug> Point<T> {
    /// Returns `Point` with given coordinates x and y.
    pub fn new(x: T, y: T) -> Self {
        Self { x, y }
    }

    /// Returns coordinate x
    pub fn get_x(&self) -> &T {
        &self.x
    }

    /// Returns coordinate y
    pub fn get_y(&self) -> &T {
        &self.y
    }
}

/// Represent a assigned point in affine coordinates
#[derive(Clone, Debug)]
pub struct AssignedPoint<T: Clone + Debug> {
    pub(crate) x: T,
    pub(crate) y: T,
}

impl<T: Clone + Debug> AssignedPoint<T> {
    /// Returns `Point` with given assigned coordinates x and y.
    pub fn new(x: T, y: T) -> Self {
        Self { x, y }
    }

    /// Returns assigned coordinate x
    pub fn get_x(&self) -> &T {
        &self.x
    }

    /// Returns assigned coordinate y
    pub fn get_y(&self) -> &T {
        &self.y
    }
}

/// Finds a point we need to subtract from the end result in the efficient batch
/// multiplication algorithm.
///
/// Computes AuxFin from AuxInit for batch multiplication
/// see https://hackmd.io/ncuKqRXzR-Cw-Au2fGzsMg?view
pub fn make_mul_aux<C: CurveAffine>(
    aux_to_add: C,
    window_size: usize,
    number_of_pairs: usize,
) -> C {
    assert!(window_size > 0);
    assert!(number_of_pairs > 0);

    let n = C::Scalar::NUM_BITS as usize;
    let mut number_of_selectors = n / window_size;
    if n % window_size != 0 {
        number_of_selectors += 1;
    }
    let mut k0 = big_uint::one();
    let one = big_uint::one();
    for i in 0..number_of_selectors {
        k0 |= &one << (i * window_size);
    }
    let k1 = (one << number_of_pairs) - 1usize;
    // k = k0* 2^n_pairs
    let k = k0 * k1;
    (-aux_to_add * big_to_fe::<C::Scalar>(k)).to_affine()
}

/// Vector of `AssignedCondition` which is the binary representation of a
/// scalar.
///
/// Allows to select values of precomputed table in efficient multiplication
/// algorithm
#[derive(Default)]
pub struct Selector<F: FieldExt>(pub(crate) Vec<AssignedCondition<F>>);

impl<F: FieldExt> fmt::Debug for Selector<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("Selector");
        for (i, bit) in self.0.iter().enumerate() {
            debug.field("window_index", &i).field("bit", bit);
        }
        debug.finish()?;
        Ok(())
    }
}

/// Vector of `Selectors` which represent the binary representation of a scalar
/// split in window sized selectors.
pub struct Windowed<F: FieldExt>(pub(crate) Vec<Selector<F>>);

impl<F: FieldExt> fmt::Debug for Windowed<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("Window");
        for (i, selector) in self.0.iter().enumerate() {
            debug
                .field("selector_index", &i)
                .field("selector", selector);
        }
        debug.finish()?;
        Ok(())
    }
}

/// Table of precomputed values for efficient multiplication algorithm.
pub struct Table<T: Clone + Debug>(pub(crate) Vec<AssignedPoint<T>>);

impl<T: Clone + Debug> fmt::Debug for Table<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("Table");
        for (i, entry) in self.0.iter().enumerate() {
            debug.field("entry_index", &i).field("point", entry);
        }
        debug.finish()?;
        Ok(())
    }
}

/// Auxiliary points for efficient multiplication algorithm
/// See: https://hackmd.io/ncuKqRXzR-Cw-Au2fGzsMg
#[derive(Debug)]
pub struct MulAux<T: Clone + Debug> {
    pub(crate) to_add: AssignedPoint<T>,
    pub(crate) to_sub: AssignedPoint<T>,
}

/// Constructs `MulAux`
impl<T: Clone + Debug> MulAux<T> {
    pub(crate) fn new(to_add: AssignedPoint<T>, to_sub: AssignedPoint<T>) -> Self {
        // TODO Should we ensure that these 2 point are coherent:
        // to_sub = (to_add * (1 << ec_order ) -1)
        MulAux { to_add, to_sub }
    }
}
