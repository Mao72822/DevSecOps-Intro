package k8s.hardening

# Extra checks on top of labs/lab9/policies/k8s-security.rego.
# Same shape as the shipped policy: walk every container of a Deployment.

# Minimum UID we accept when a container pins runAsUser explicitly.
# UIDs below 10000 overlap system/service accounts on most host images,
# so a container escape lands as a real, possibly privileged, host user.
min_uid := 10000

containers contains c if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
}

# DENY: image must be pinned by digest, not by a mutable tag.
# A tag (even a non-latest one like :v19.0.0) can be re-pushed; a digest cannot,
# so what was scanned in CI is exactly what runs.
deny contains msg if {
  c := containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image %q must be pinned by digest (@sha256:...)", [c.name, c.image])
}

# WARN: an explicit runAsUser must be a high, non-system UID.
# (Absent runAsUser is fine: runAsNonRoot in the shipped policy already forbids root.)
warn contains msg if {
  c := containers[_]
  uid := c.securityContext.runAsUser
  uid < min_uid
  msg := sprintf("container %q runAsUser %d is below %d; use a high UID that does not exist on the host", [c.name, uid, min_uid])
}
