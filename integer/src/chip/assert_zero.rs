use super::IntegerChip;
use crate::rns::MaybeReduced;
use crate::{AssignedInteger, FieldExt};
use halo2::plonk::Error;

use maingate::{halo2, AssignedValue, MainGateInstructions, RangeInstructions, RegionCtx, Term};

impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub(super) fn assert_zero_generic(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let witness: MaybeReduced<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> =
            a.integer().as_ref().map(|a_int| a_int.reduce()).into();
        let quotient = witness.short();

        // Apply ranges
        let range_chip = self.range_chip();
        let quotient = range_chip.range_value(ctx, &quotient.into(), BIT_LEN_LIMB)?;
        let residues = witness
            .residues()
            .iter()
            .map(|v| range_chip.range_value(ctx, &v.into(), self.rns.red_v_bit_len))
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        // Assign intermediate values
        let t: Vec<AssignedValue<N>> = a
            .limbs()
            .into_iter()
            .zip(self.rns.negative_wrong_modulus_decomposed.into_iter())
            .map(|(a_i, w_i)| {
                main_gate.compose(
                    ctx,
                    &[
                        Term::Assigned(a_i.into(), one),
                        Term::Assigned(quotient, w_i),
                    ],
                    zero,
                )
            })
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        // Constrain residues
        let lsh_one = self.rns.left_shifter(1);
        let lsh_two = self.rns.left_shifter(2);
        let mut carry = Term::Zero;
        for (t_chunk, v) in t.chunks(2).zip(residues.into_iter()) {
            if t_chunk.len() == 2 {
                let (t_lo, t_hi) = (t_chunk[0], t_chunk[1]);
                main_gate.assert_zero_sum(
                    ctx,
                    &[
                        // R^2 * v = t_lo + R * t_hi + carry
                        Term::Assigned(t_lo, one),
                        Term::Assigned(t_hi, lsh_one),
                        Term::Assigned(v, -lsh_two),
                        carry.clone(),
                    ],
                    zero,
                )?;
                carry = Term::Assigned(v, one);
            } else {
                let t = t[0];
                main_gate.assert_zero_sum(
                    ctx,
                    &[
                        // R * v = t + carry
                        Term::Assigned(t, one),
                        Term::Assigned(v, -lsh_one),
                        carry.clone(),
                    ],
                    zero,
                )?;
            }
        }

        Ok(())
    }
}
