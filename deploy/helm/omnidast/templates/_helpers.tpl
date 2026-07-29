{{- define "yubel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "yubel.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "yubel.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "yubel.labels" -}}
app.kubernetes.io/name: {{ include "yubel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "yubel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "yubel.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
