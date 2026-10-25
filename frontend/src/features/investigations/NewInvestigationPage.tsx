import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Play } from "lucide-react";
import { useRef, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError } from "@/api/client";
import { endpoints } from "@/api/endpoints";
import { Callout } from "@/components/shared/Callout";
import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Field, Input, Select, Textarea } from "@/components/ui/field";
import { useAccess } from "@/features/auth/AuthProvider";
import type { CreateInvestigationRequest, TargetKind } from "@/types/api";
import { VoiceRequest, type AppliedSpeech } from "@/features/speech/VoiceRequest";
import { ResourceHealthPanel } from "./ResourceHealth";
import { startExecution } from "./execution";

export const NAME_PATTERN = /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/;
const KINDS: TargetKind[] = ["Deployment", "StatefulSet", "DaemonSet", "Pod"];
const WORKLOAD_QUESTION = "Why is this workload unhealthy?";
const NAMESPACE_QUESTION = "Which workloads are unhealthy, and why?";

type Scope = "workload" | "namespace";

interface FormErrors {
  namespace?: string;
  name?: string;
  question?: string;
}

export function validate(values: { namespace: string; scope: Scope; name: string; question: string }): FormErrors {
  const errors: FormErrors = {};

  if (!values.namespace) errors.namespace = "Choose a namespace.";

  if (values.scope === "workload") {
    if (!values.name.trim()) errors.name = "Enter the exact workload name.";
    else if (values.name.length > 63 || !NAME_PATTERN.test(values.name)) {
      errors.name = "Use lowercase letters, digits and hyphens only (max 63 characters).";
    }
  }

  if (!values.question.trim()) errors.question = "Enter the question to investigate.";
  else if (values.question.length > 3800) errors.question = "The question is too long.";

  return errors;
}

export function NewInvestigationPage() {
  const { access } = useAccess();
  const namespaces = access?.allowed_namespaces ?? [];
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const submitted = useRef(false);

  const [namespace, setNamespace] = useState("");
  const chosenNamespace = namespace || namespaces[0] || "";
  const [scope, setScope] = useState<Scope>("workload");
  const [kind, setKind] = useState<TargetKind>("Deployment");
  const [name, setName] = useState("");
  const [question, setQuestion] = useState(WORKLOAD_QUESTION);
  const [touched, setTouched] = useState(false);

  const errors = validate({ namespace: chosenNamespace, scope, name, question });

  const create = useMutation({
    // Never retried: a lost response must not create a second investigation.
    retry: false,
    mutationFn: (body: CreateInvestigationRequest) => endpoints.create(body),
    onSuccess: (record) => {
      startExecution(queryClient, record.investigation_id);
      void navigate(`/investigations/${encodeURIComponent(record.investigation_id)}`);
    },
    onError: () => {
      submitted.current = false;
    },
  });

  function clearSubmitError() {
    if (create.isError) create.reset();
  }

  function chooseScope(next: Scope) {
    setScope(next);
    setQuestion((current) =>
      current === WORKLOAD_QUESTION || current === NAMESPACE_QUESTION
        ? next === "workload"
          ? WORKLOAD_QUESTION
          : NAMESPACE_QUESTION
        : current,
    );
    clearSubmitError();
  }

  function applySpeech(speech: AppliedSpeech) {
    setScope(speech.scope);

    if (speech.scope === "workload" && speech.name) {
      setName(speech.name);
      if (speech.kind) setKind(speech.kind);
    }

    setQuestion(speech.question);
    setTouched(false);
    clearSubmitError();
  }

  function startInvestigation() {
    setTouched(true);
    if (Object.keys(errors).length > 0 || submitted.current || create.isPending) return;

    submitted.current = true;
    create.mutate({
      namespace: chosenNamespace,
      question: question.trim(),
      ...(scope === "workload" ? { target: { kind, name } } : { namespace_wide: true }),
    });
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    startInvestigation();
  }

  const failure = create.error instanceof ApiError ? create.error : null;
  const uncertain = failure !== null && (failure.kind === "network" || failure.kind === "timeout");

  return (
    <>
      <PageHeader
        title="New investigation"
        description="Choose one workload, or deliberately investigate a whole namespace."
      />

      {failure ? (
        uncertain ? (
          <Callout tone="warning" title="We could not confirm whether the investigation was created">
            {failure.message} To avoid a duplicate, check{" "}
            <Link to="/investigations" className="text-accent underline">
              history
            </Link>{" "}
            before submitting again.
          </Callout>
        ) : (
          <Callout tone="error" title={failure.kind === "rejected" ? "The request was not accepted" : "Could not start the investigation"}>
            {failure.message}
          </Callout>
        )
      ) : null}

      <Card className="max-w-xl">
        <CardBody className="p-5">
          <form onSubmit={submit} className="space-y-5" noValidate aria-label="New investigation">
            <Field label="Namespace" htmlFor="namespace" error={touched ? errors.namespace : null} hint="Namespaces available in this demo.">
              <Select
                id="namespace"
                value={chosenNamespace}
                onChange={(event) => {
                  setNamespace(event.target.value);
                  clearSubmitError();
                }}
              >
                {namespaces.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </Select>
            </Field>

            <fieldset className="space-y-2">
              <legend className="mb-1.5 text-[13px] font-medium">Scope</legend>
              <div className="grid grid-cols-2 gap-1 rounded-md border border-border bg-surface-2 p-0.5">
                {(
                  [
                    ["workload", "One workload"],
                    ["namespace", "Whole namespace (broad)"],
                  ] as const
                ).map(([value, label]) => (
                  <label
                    key={value}
                    className="flex cursor-pointer items-center justify-center rounded px-2 py-1.5 text-[13px] text-muted transition-colors has-[:checked]:bg-surface has-[:checked]:font-medium has-[:checked]:text-foreground has-[:checked]:shadow-sm has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-ring"
                  >
                    <input
                      type="radio"
                      name="scope"
                      className="sr-only"
                      checked={scope === value}
                      onChange={() => chooseScope(value)}
                    />
                    {label}
                  </label>
                ))}
              </div>
              {scope === "namespace" ? (
                <p className="text-xs text-warning">
                  Inspects the namespace as a whole and is labelled as such in the report. It is never used as a fallback for an unresolved workload.
                </p>
              ) : null}
            </fieldset>

            {scope === "workload" ? (
              <div className="grid gap-4 sm:grid-cols-[10rem_1fr]">
                <Field label="Resource kind" htmlFor="kind">
                  <Select id="kind" value={kind} onChange={(event) => setKind(event.target.value as TargetKind)}>
                    {KINDS.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field
                  label="Workload name"
                  htmlFor="workload-name"
                  error={touched ? errors.name : null}
                  hint="Exact name, for example bad-readiness. Never matched by prefix."
                >
                  <Input
                    id="workload-name"
                    value={name}
                    onChange={(event) => {
                      setName(event.target.value.trim());
                      clearSubmitError();
                    }}
                    autoComplete="off"
                    spellCheck={false}
                    aria-invalid={touched && errors.name ? true : undefined}
                  />
                </Field>
              </div>
            ) : null}

            <ResourceHealthPanel
              namespace={namespace}
              kind={kind}
              name={name}
              scope={scope}
              nameValid={scope === "namespace" || (name.trim().length > 0 && !errors.name)}
              onInvestigate={startInvestigation}
            />

            <VoiceRequest namespace={namespace} onApply={applySpeech} />

            <Field label="Question" htmlFor="question" error={touched ? errors.question : null}>
              <Textarea
                id="question"
                value={question}
                onChange={(event) => {
                  setQuestion(event.target.value);
                  clearSubmitError();
                }}
                maxLength={3800}
                aria-invalid={touched && errors.question ? true : undefined}
              />
            </Field>

            <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4">
              <Button type="submit" variant="primary" disabled={create.isPending}>
                <Play aria-hidden="true" className="size-3.5" />
                {create.isPending ? "Creating…" : "Investigate"}
              </Button>
              <p className="text-xs text-muted">Read-only. No change is made to the cluster.</p>
            </div>
          </form>
        </CardBody>
      </Card>
    </>
  );
}
