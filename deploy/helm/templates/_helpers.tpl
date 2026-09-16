{{- define "decrypt0rx.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "decrypt0rx.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "decrypt0rx.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "decrypt0rx.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "decrypt0rx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "decrypt0rx.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "decrypt0rx.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Environment shared by the proxy and the API. */}}
{{- define "decrypt0rx.commonEnv" -}}
- name: DECRYPT0RX_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "decrypt0rx.secretName" . }}
      key: databaseUrl
- name: DECRYPT0RX_MASTER_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "decrypt0rx.secretName" . }}
      key: masterKey
- name: DECRYPT0RX_S3_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "decrypt0rx.secretName" . }}
      key: s3AccessKey
- name: DECRYPT0RX_S3_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "decrypt0rx.secretName" . }}
      key: s3SecretKey
- name: DECRYPT0RX_REDIS_URL
  value: {{ .Values.redis.url | quote }}
- name: DECRYPT0RX_S3_ENDPOINT_URL
  value: {{ .Values.objectStorage.endpoint | quote }}
- name: DECRYPT0RX_S3_BUCKET
  value: {{ .Values.objectStorage.bucket | quote }}
- name: DECRYPT0RX_S3_REGION
  value: {{ .Values.objectStorage.region | quote }}
- name: DECRYPT0RX_LOG_LEVEL
  value: {{ .Values.logging.level | quote }}
- name: DECRYPT0RX_LOG_FORMAT
  value: {{ .Values.logging.format | quote }}
{{- end -}}
