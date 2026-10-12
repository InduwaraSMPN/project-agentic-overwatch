{{/*
deploy/helm/agentic-overwatch/templates/_helpers.tpl

Small, deliberately few helpers. Object names below are mostly left as the literals the
source manifests already use (guardian, evidence-aggregator, audit-forwarder, ...) rather than
prefixed with the release name, because this chart packages a singleton reference-monitor
deployment (one Guardian, one cluster) rather than a multi-tenant workload, and literal names
keep `helm template` output diffable against guardian/deploy/*.yaml and monitor/deploy/*.yaml.
See docs/adr/ADR-113-helm-chart-packaging.md.
*/}}

{{- define "agentic-overwatch.chartLabels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/part-of: agentic-overwatch
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
