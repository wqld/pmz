use ctrl::{Error, InterceptRule, Result};

use futures::StreamExt;
use kube::{
    Api, Client, ResourceExt,
    runtime::controller::{Action, Controller},
};
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), kube::Error> {
    env_logger::init();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let client = Client::try_default().await?;
    let intercept_rules = Api::<InterceptRule>::all(client);

    Controller::new(intercept_rules.clone(), Default::default())
        .run(reconcile, error_policy, Arc::new(()))
        .for_each(|_| futures::future::ready(()))
        .await;

    Ok(())
}

async fn reconcile(obj: Arc<InterceptRule>, _ctx: Arc<()>) -> Result<Action> {
    println!("reconcile request: {}", obj.name_any());
    Ok(Action::requeue(Duration::from_secs(3600)))
}

fn error_policy(_object: Arc<InterceptRule>, _err: &Error, _ctx: Arc<()>) -> Action {
    Action::requeue(Duration::from_secs(5))
}
