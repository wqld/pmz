use ctrl::InterceptRule;
use kube::CustomResourceExt;

fn main() {
    print!("{}", serde_json::to_string(&InterceptRule::crd()).unwrap())
}
