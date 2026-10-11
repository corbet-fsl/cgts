//! Original single-use receipt staging in a caller-owned admission transaction.
use super::*;

impl LibsqlStore {
    /// Stage the original single-use marker in this exact database/community's
    /// existing transaction. This method neither opens nor commits a writer.
    /// The caller must first obtain the claim from genuine leaf verification and
    /// commit it together with the authorized lifecycle effect.
    ///
    /// Ownership is returned only on success. Refusal, storage error or cancelled
    /// future drops the transaction, rolling back ALL previously staged owners;
    /// ignoring an error cannot leave a partially staged writer to commit.
    /// A successful return is not a durable redemption acknowledgement.
    pub async fn claim_in_transaction(
        &self,
        mut transaction: crlt::Transaction,
        claim: &Claim,
    ) -> Result<crlt::Transaction> {
        if !transaction.belongs_to(&self.db) {
            return Err(Error::Scope);
        }
        stage_claim(&mut transaction, claim).await?;
        Ok(transaction)
    }
}

pub(super) async fn stage_claim(transaction: &mut crlt::Transaction, claim: &Claim) -> Result<()> {
    if !transaction
        .query(CLAIM, params![claim.domain.clone(), claim.marker.clone()])
        .await?
        .is_empty()
    {
        return Err(Error::Refused);
    }
    transaction
        .execute(SPEND, params![claim.domain.clone(), claim.marker.clone()])
        .await?;
    Ok(())
}
