{{/*
==============================================================================
DGIP Helm Chart — Reusable Template Helpers
==============================================================================
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "dgip.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name, truncated at 63 chars for DNS label compliance.
*/}}
{{- define "dgip.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version for the `helm.sh/chart` label.
*/}}
{{- define "dgip.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Standard Kubernetes recommended labels applied to all chart resources.
*/}}
{{- define "dgip.labels" -}}
helm.sh/chart: {{ include "dgip.chart" . }}
{{ include "dgip.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: dgip
{{- end }}

{{/*
Selector labels for the stateless DGIP API Deployment and Service.
*/}}
{{- define "dgip.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dgip.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end }}

{{/*
Fully qualified name and selector labels for the optional bundled PostgreSQL StatefulSet.
*/}}
{{- define "dgip.postgresql.fullname" -}}
{{- printf "%s-postgresql" (include "dgip.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dgip.postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dgip.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgresql
{{- end }}

{{/*
Resolve the ServiceAccount name to use.
*/}}
{{- define "dgip.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "dgip.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve the Secret name and key supplying DGIP_DATABASE_URL.
*/}}
{{- define "dgip.dbUrlSecretName" -}}
{{- if and (not .Values.database.internal.enabled) .Values.database.external.existingSecret }}
{{- .Values.database.external.existingSecret }}
{{- else }}
{{- include "dgip.fullname" . }}
{{- end }}
{{- end }}

{{- define "dgip.dbUrlSecretKey" -}}
{{- if and (not .Values.database.internal.enabled) .Values.database.external.existingSecret }}
{{- .Values.database.external.existingSecretKey }}
{{- else }}
{{- "database-url" }}
{{- end }}
{{- end }}

{{/*
Pod-level SecurityContext helper:
When `openshift.enabled` is true, omit `runAsUser`, `runAsGroup`, and `fsGroup`
so OpenShift's `restricted-v2` SCC controller assigns UIDs from the namespace range.
*/}}
{{- define "dgip.podSecurityContext" -}}
{{- if .Values.openshift.enabled }}
{{- $osc := omit .Values.podSecurityContext "runAsUser" "runAsGroup" "fsGroup" }}
{{- toYaml $osc }}
{{- else }}
{{- toYaml .Values.podSecurityContext }}
{{- end }}
{{- end }}

{{/*
Container-level SecurityContext helper:
Strips `runAsUser` and `runAsGroup` if set when `openshift.enabled` is true.
*/}}
{{- define "dgip.containerSecurityContext" -}}
{{- if .Values.openshift.enabled }}
{{- $csc := omit .Values.securityContext "runAsUser" "runAsGroup" }}
{{- toYaml $csc }}
{{- else }}
{{- toYaml .Values.securityContext }}
{{- end }}
{{- end }}
