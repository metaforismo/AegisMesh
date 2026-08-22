{{/*
Deterministic naming: "<release>-<chart>", or plain chart name when the
release already is named aegismesh (standard Helm convention).
*/}}
{{- define "aegismesh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "aegismesh.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := include "aegismesh.name" . }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Selector labels — the only identity Deployment/Service match on. */}}
{{- define "aegismesh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aegismesh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Full label set for top-level objects. All values are deterministic:
no timestamps, no random data, no release time.
*/}}
{{- define "aegismesh.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | quote }}
{{ include "aegismesh.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | replace "+" "_" | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aegismesh
{{- end }}

{{/*
Container image reference. Empty tag falls back to the immutable-by-policy
chart appVersion; an explicit "latest" forces Always pull semantics.
*/}}
{{- define "aegismesh.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{- define "aegismesh.pullPolicy" -}}
{{- if .Values.image.pullPolicy -}}
{{ .Values.image.pullPolicy }}
{{- else if eq (default "" .Values.image.tag) "latest" -}}
Always
{{- else -}}
IfNotPresent
{{- end -}}
{{- end -}}

{{/*
The mesh.yaml document, rendered from the structured values map.
`required` fails fast with an actionable message instead of emitting a
useless empty config. Rendered identically for the ConfigMap and for the
pod-template checksum annotation so they can never drift apart.
No `tpl` is applied to this content: values are data, never templates.
*/}}
{{- define "aegismesh.meshYaml" -}}
{{- $cfg := required "values.meshConfig must hold a complete mesh.yaml document (api_version plus at least one sensor)" .Values.meshConfig -}}
{{- toYaml $cfg -}}
{{- end }}
