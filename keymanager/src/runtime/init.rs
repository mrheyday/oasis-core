use futures::executor::block_on;
use oasis_core_runtime::{
    dispatcher::{Initializer, PostInitState, PreInitState},
    enclave_rpc::dispatcher::Handler,
    host::Host,
};

use crate::{
    churp::Churp,
    policy::{set_trusted_signers, TrustedSigners},
};

use super::secrets::Secrets;

/// Initialize a keymanager with trusted signers.
pub fn new_keymanager(signers: TrustedSigners) -> Box<dyn Initializer> {
    // Initializer.
    let init = move |state: PreInitState<'_>| -> PostInitState {
        // It's not the most elegant solution, but it gets the job done.
        // We could improve this by including node identity in the host info
        // or by removing the initializer.
        let node_id = block_on(state.protocol.identity()).unwrap();

        // Initialize the set of trusted signers.
        set_trusted_signers(signers.clone());

        let secrets = Box::leak(Box::new(Secrets::new(
            state.identity.clone(),
            state.consensus_verifier.clone(),
            state.protocol.clone(),
        )));

        let churp = Box::leak(Box::new(Churp::new(
            node_id,
            state.identity.clone(),
            state.protocol.clone(),
            state.consensus_verifier.clone(),
        )));

        state.rpc_dispatcher.add_methods(secrets.methods());
        state.rpc_dispatcher.add_methods(churp.methods());

        // No transaction dispatcher.
        PostInitState::default()
    };

    Box::new(init)
}
