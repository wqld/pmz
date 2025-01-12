# pmz

Panmunzom (pmz) enables access to Kubernetes services directly using their service domain,
such as `name.namespace.svc`, from your local machine.

## Feature Scope

pmz is being developed to provide a convenient way to access workloads on a Kubernetes cluster from your local machine.

Here are the features currently planned for pmz:

- *Local access to workloads using Kubernetes service FQDNs*: Access cluster workloads seamlessly using their fully qualified domain names from your local environment. (implemented)
- *Custom domain routing*: Configure custom domains to route to specific workloads, giving you flexibility and control over access.
- *Sidecarless interception*: Intercept requests to specific Kubernetes workloads locally without requiring pod restarts or sidecar injection.
- *Domain-based personal intercepts*: Enable personal intercepts based on domain names rather than relying on header-based routing, providing a more streamlined and user-friendly experience.
