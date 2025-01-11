#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("duplicate shareholder")]
    DuplicateShareholder,
    #[error("invalid handoff kind")]
    InvalidKind,
    #[error("invalid polynomial")]
    InvalidPolynomial,
    #[error("insecure bivariate polynomial")]
    InsecureBivariatePolynomial,
    #[error("invalid switch point")]
    InvalidSwitchPoint,
    #[error("invalid state")]
    InvalidState,
    #[error("not enough bivariate shares")]
    NotEnoughBivariateShares,
    #[error("not enough shareholders")]
    NotEnoughShareholders,
    #[error("not enough switch points")]
    NotEnoughSwitchPoints,
    #[error("merging not finished")]
    MergingNotFinished,
    #[error("polynomial degree mismatch")]
    PolynomialDegreeMismatch,
    #[error("polynomial generation failed")]
    PolynomialGenerationFailed,
    #[error("shareholder encoding failed")]
    ShareholderEncodingFailed,
    #[error("shareholder proactivization already completed")]
    ShareholderProactivizationCompleted,
    #[error("shareholder identity mismatch")]
    ShareholderIdentityMismatch,
    #[error("shareholder identity required")]
    ShareholderIdentityRequired,
    #[error("threshold too large")]
    ThresholdTooLarge,
    #[error("too many switch points")]
    TooManySwitchPoints,
    #[error("unknown shareholder")]
    UnknownShareholder,
    #[error("verification matrix dimension mismatch")]
    VerificationMatrixDimensionMismatch,
    #[error("verification matrix zero-hole mismatch")]
    VerificationMatrixZeroHoleMismatch,
    #[error("verification matrix required")]
    VerificationMatrixRequired,
    #[error("zero value shareholder")]
    ZeroValueShareholder,
}
