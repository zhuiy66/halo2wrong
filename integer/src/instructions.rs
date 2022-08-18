use crate::maingate::{halo2, AssignedCondition, RegionCtx};
use halo2::arithmetic::FieldExt;
use halo2::plonk::Error;
use maingate::halo2::circuit::Value;
use maingate::{AssignedValue, CombinationOptionCommon, MainGate, MainGateInstructions, Term};
use std::fmt::Debug;

/// Signals the range mode that should be applied while assigning a new
/// [`Integer`]
#[derive(Debug)]
pub enum Range {
    /// Allowed range for multiplication result
    Remainder,
    /// Maximum allowed range for a multiplication operation
    Operand,
    /// Maximum allowed range for an integer for multiplicaiton quotient
    MulQuotient,
    /// Signal for unreduced value
    Unreduced,
}

/// Common functionality for non native integer constraints
pub trait IntegerInstructions<W: FieldExt, N: FieldExt>: Clone + Debug {
    /// `MainGateInstructions` shared among all the other chips
    type MainGate: MainGateInstructions<N>;

    /// Representation of an wrong field integer
    type Integer: Clone + Debug;

    /// Representation of an assigned integer
    type AssignedInteger: Clone + Debug;

    /// Returns reference to `IntegerInstructions::MainGate`
    fn main_gate(&self) -> &Self::MainGate;

    /// Create a new `Integer` from wrong field element.
    fn integer(&self, fe: W) -> Self::Integer;

    /// Assigns an [`Integer`] to a cell in the circuit with range check for the
    /// appropriate [`Range`].
    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        integer: Value<Self::Integer>,
        range: Range,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Assigns an [`Integer`] constant to a cell in the circuit returning an
    /// [`AssignedInteger`].
    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        integer: W,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Decomposes an [`AssignedInteger`] into its bit representation.
    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        integer: &Self::AssignedInteger,
    ) -> Result<Vec<AssignedCondition<N>>, Error>;

    /// Adds 2 [`AssignedInteger`].
    fn add(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Adds up 3 [`AssignedInteger`]
    fn add_add(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b_0: &Self::AssignedInteger,
        b_1: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Adds an [`AssignedInteger`] and a constant.
    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::Integer,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Multiplies an [`AssignedInteger`] by 2.
    fn mul2(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Multiplies an [`AssignedInteger`] by 3.
    fn mul3(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Substracts an [`AssignedInteger`].
    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Substracts 2 [`AssignedInteger`].
    fn sub_sub(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b_0: &Self::AssignedInteger,
        b_1: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Multiplies an [`AssignedInteger`] by -1.
    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Multiplies 2 [`AssignedInteger`].
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Multiplies [`AssignedInteger`] by constant.
    fn mul_constant(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::Integer,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Check 2 [`AssignedInteger`] are inverses, equivalently their product is
    /// 1.
    fn mul_into_one(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<(), Error>;

    /// Squares an [`AssignedInteger`].
    fn square(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Divides 2 [`AssignedInteger`]. An [`AssignedCondition`] is returned
    /// along with the division result indicating if the operation was
    /// successful.
    fn div(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<(Self::AssignedInteger, AssignedCondition<N>), Error>;

    /// Divides 2 [`AssignedInteger`]. Assumes denominator is not zero.
    fn div_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Inverts an [`AssignedInteger`]. An [`AssignedCondition`] is returned
    /// along with the inversion result indicating if the operation was
    /// successful
    fn invert(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<(Self::AssignedInteger, AssignedCondition<N>), Error>;

    /// Inverts an [`AssignedInteger`]. Assumes the input is not zero.
    fn invert_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Applies reduction to an [`AssignedInteger`]. Reduces the input less than
    /// next power of two of the modulus
    fn reduce(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Constraints that two [`AssignedInteger`] are equal.
    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<(), Error>;

    /// Constraints that limbs of two [`AssignedInteger`] are equal.
    fn assert_strict_equal(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<(), Error>;

    /// Constraints that two [`AssignedInteger`] are not equal.
    fn assert_not_equal(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<(), Error>;

    /// Constraints that an [`AssignedInteger`] is not equal to zero
    fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<(), Error>;

    /// Constraints that an [`AssignedInteger`] is equal to zero
    fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<(), Error>;

    /// Constraints that limbs of an [`AssignedInteger`] is equal to zero
    fn assert_strict_zero(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<(), Error>;

    /// Constraints that first limb of an [`AssignedInteger`] is equal to one
    /// and others are zero
    fn assert_strict_one(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<(), Error>;

    /// Constraints that first limb of an [`AssignedInteger`] is a bit
    /// and others are zero
    fn assert_strict_bit(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<(), Error>;

    /// Constraints that an [`AssignedInteger`] is less than modulus
    fn assert_in_field(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        input: &Self::AssignedInteger,
    ) -> Result<(), Error>;

    /// Given an [`AssignedCondition`] returns picks one of two
    /// [`AssignedInteger`]
    fn select(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
        cond: &AssignedCondition<N>,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Given an [`AssignedCondition`] returns picks either an
    /// [`AssignedInteger`] or an unassigned integer
    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::Integer,
        cond: &AssignedCondition<N>,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Applies % 2 to the given input
    fn sign(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<AssignedCondition<N>, Error>;
}

// Native field `IntegerInstructions` implementation for `MainGate`
impl<F: FieldExt> IntegerInstructions<F, F> for MainGate<F> {
    type MainGate = Self;
    type AssignedInteger = AssignedValue<F>;
    type Integer = F;

    fn main_gate(&self) -> &Self::MainGate {
        self
    }

    fn integer(&self, fe: F) -> F {
        fe
    }

    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        integer: Value<F>,
        _: Range,
    ) -> Result<AssignedValue<F>, Error> {
        self.assign_value(ctx, integer)
    }

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        integer: F,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::assign_constant(self, ctx, integer)
    }

    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        integer: &AssignedValue<F>,
    ) -> Result<Vec<AssignedCondition<F>>, Error> {
        MainGateInstructions::to_bits(self, ctx, integer, F::NUM_BITS as usize)
    }

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::add(self, ctx, a, b)
    }

    fn add_add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b_0: &AssignedValue<F>,
        b_1: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::compose(
            self,
            ctx,
            &[
                Term::assigned_to_add(a),
                Term::assigned_to_add(b_0),
                Term::assigned_to_add(b_1),
            ],
            F::zero(),
        )
    }

    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &F,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::add_constant(self, ctx, a, *b)
    }

    fn mul2(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::mul2(self, ctx, a)
    }

    fn mul3(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::mul3(self, ctx, a)
    }

    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::sub(self, ctx, a, b)
    }

    fn sub_sub(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b_0: &AssignedValue<F>,
        b_1: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::sub_sub_with_constant(self, ctx, a, b_0, b_1, F::zero())
    }

    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::neg_with_constant(self, ctx, a, F::zero())
    }

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::mul(self, ctx, a, b)
    }

    fn mul_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &F,
    ) -> Result<AssignedValue<F>, Error> {
        Ok(MainGateInstructions::apply(
            self,
            ctx,
            [
                Term::Assigned(a, *b),
                Term::unassigned_to_sub(a.value().map(|a| *a * b)),
            ],
            F::zero(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?
        .swap_remove(1))
    }

    fn mul_into_one(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<(), Error> {
        MainGateInstructions::apply(
            self,
            ctx,
            [Term::assigned_to_mul(a), Term::assigned_to_mul(b)],
            -F::one(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;
        Ok(())
    }

    fn square(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::mul(self, ctx, a, a)
    }

    fn div(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<(AssignedValue<F>, AssignedCondition<F>), Error> {
        MainGateInstructions::div(self, ctx, a, b)
    }

    fn div_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::div_unsafe(self, ctx, a, b)
    }

    fn invert(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(AssignedValue<F>, AssignedCondition<F>), Error> {
        MainGateInstructions::invert(self, ctx, a)
    }

    fn invert_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::invert_unsafe(self, ctx, a)
    }

    fn reduce(
        &self,
        _: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        Ok(a.clone())
    }

    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<(), Error> {
        MainGateInstructions::assert_equal(self, ctx, a, b)
    }

    fn assert_strict_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<(), Error> {
        MainGateInstructions::assert_equal(self, ctx, a, b)
    }

    fn assert_not_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<(), Error> {
        MainGateInstructions::assert_not_equal(self, ctx, a, b)
    }

    fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        MainGateInstructions::assert_not_zero(self, ctx, a)
    }

    fn assert_zero(&self, ctx: &mut RegionCtx<'_, F>, a: &AssignedValue<F>) -> Result<(), Error> {
        MainGateInstructions::assert_zero(self, ctx, a)
    }

    fn assert_strict_zero(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        MainGateInstructions::assert_zero(self, ctx, a)
    }

    fn assert_strict_one(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        MainGateInstructions::assert_one(self, ctx, a)
    }

    fn assert_strict_bit(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        MainGateInstructions::assert_bit(self, ctx, a)
    }

    fn assert_in_field(&self, _: &mut RegionCtx<'_, F>, _: &AssignedValue<F>) -> Result<(), Error> {
        Ok(())
    }

    fn select(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        cond: &AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::select(self, ctx, a, b, cond)
    }

    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &F,
        cond: &AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error> {
        MainGateInstructions::select_or_assign(self, ctx, a, *b, cond)
    }

    fn sign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        MainGateInstructions::sign(self, ctx, a)
    }
}
