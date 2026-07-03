import { useEffect, useState } from 'react';
import { Modal } from '@/shared/ui/feedback';
import { Button, Input, Label, Select } from '@/shared/ui/core';
import { Alert } from '@/shared/ui/data-display';
import { OWNER_PIPELINE_STAGES } from '../constants/ownerPipelineConstants';
import type {
  CreatePipelineRecordRequest,
  PipelineRecord,
} from '../types/ownerPortalApiTypes';

// Create / edit form for a live pipeline record (POST/PATCH /owner/pipeline).
interface OwnerPipelineFormModalProps {
  open: boolean;
  record: PipelineRecord | null;
  isSaving: boolean;
  errorMessage: string | null;
  onClose: () => void;
  onSubmit: (values: CreatePipelineRecordRequest) => void;
}

const EMPTY: CreatePipelineRecordRequest = {
  name: '',
  company: '',
  email: '',
  phone: '',
  productInterest: '',
  source: '',
  stage: OWNER_PIPELINE_STAGES[0],
  conversionPct: 0,
};

export function OwnerPipelineFormModal({
  open,
  record,
  isSaving,
  errorMessage,
  onClose,
  onSubmit,
}: OwnerPipelineFormModalProps) {
  const [values, setValues] = useState<CreatePipelineRecordRequest>(EMPTY);

  useEffect(() => {
    if (!open) return;
    setValues(
      record
        ? {
            name: record.name,
            company: record.company ?? '',
            email: record.email ?? '',
            phone: record.phone ?? '',
            productInterest: record.productInterest ?? '',
            source: record.source ?? '',
            stage: record.stage,
            conversionPct: record.conversionPct,
          }
        : EMPTY,
    );
  }, [open, record]);

  const set = <K extends keyof CreatePipelineRecordRequest>(
    key: K,
    value: CreatePipelineRecordRequest[K],
  ) => setValues((prev) => ({ ...prev, [key]: value }));

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    onSubmit({ ...values, name: values.name.trim() });
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={record ? 'Edit pipeline record' : 'New pipeline record'}
      footer={
        <div className="flex justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button
            size="sm"
            form="owner-pipeline-form"
            type="submit"
            disabled={isSaving || values.name.trim() === ''}
          >
            {isSaving ? 'Saving…' : record ? 'Save changes' : 'Create record'}
          </Button>
        </div>
      }
    >
      <form id="owner-pipeline-form" onSubmit={submit} className="space-y-4">
        {errorMessage && <Alert tone="r">{errorMessage}</Alert>}

        <div className="space-y-1.5">
          <Label htmlFor="pl-name">Name</Label>
          <Input
            id="pl-name"
            value={values.name}
            onChange={(e) => set('name', e.target.value)}
            required
          />
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="pl-company">Company</Label>
            <Input
              id="pl-company"
              value={values.company}
              onChange={(e) => set('company', e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="pl-email">Email</Label>
            <Input
              id="pl-email"
              type="email"
              value={values.email}
              onChange={(e) => set('email', e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="pl-phone">Phone</Label>
            <Input
              id="pl-phone"
              value={values.phone}
              onChange={(e) => set('phone', e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="pl-product">Product interest</Label>
            <Input
              id="pl-product"
              value={values.productInterest}
              onChange={(e) => set('productInterest', e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="pl-source">Source</Label>
            <Input
              id="pl-source"
              value={values.source}
              onChange={(e) => set('source', e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="pl-stage">Stage</Label>
            <Select
              id="pl-stage"
              value={values.stage}
              onChange={(e) => set('stage', e.target.value)}
            >
              {OWNER_PIPELINE_STAGES.map((stage) => (
                <option key={stage} value={stage}>
                  {stage}
                </option>
              ))}
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="pl-conversion">Conversion %</Label>
            <Input
              id="pl-conversion"
              type="number"
              min={0}
              max={100}
              value={values.conversionPct}
              onChange={(e) => set('conversionPct', Number(e.target.value))}
            />
          </div>
        </div>
      </form>
    </Modal>
  );
}
