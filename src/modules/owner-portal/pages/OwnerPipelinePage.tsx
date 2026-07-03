import { useState } from 'react';
import { Plus } from 'lucide-react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { Button } from '@/shared/ui/core';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerLivePipelineBoard } from '../components/OwnerLivePipelineBoard';
import { OwnerPipelineFormModal } from '../components/OwnerPipelineFormModal';
import { OwnerQueryState } from '../components/OwnerQueryState';
import {
  useCreatePipelineRecordMutation,
  useDeletePipelineRecordMutation,
  useListPipelineQuery,
  useUpdatePipelineRecordMutation,
} from '../api/ownerPortalApi';
import type {
  CreatePipelineRecordRequest,
  PipelineRecord,
} from '../types/ownerPortalApiTypes';

export function OwnerPipelinePage() {
  const { data, isLoading, error } = useListPipelineQuery({ page: 1, limit: 100 });
  const [createRecord, { isLoading: isCreating }] = useCreatePipelineRecordMutation();
  const [updateRecord, { isLoading: isUpdating }] = useUpdatePipelineRecordMutation();
  const [deleteRecord] = useDeletePipelineRecordMutation();

  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<PipelineRecord | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const records = data?.data ?? [];

  const openCreate = () => {
    setEditing(null);
    setSubmitError(null);
    setModalOpen(true);
  };

  const openEdit = (record: PipelineRecord) => {
    setEditing(record);
    setSubmitError(null);
    setModalOpen(true);
  };

  const onSubmit = async (values: CreatePipelineRecordRequest) => {
    setSubmitError(null);
    try {
      if (editing) {
        await updateRecord({ id: editing.id, patch: values }).unwrap();
        toast.success('Pipeline record updated.');
      } else {
        await createRecord(values).unwrap();
        toast.success('Pipeline record created.');
      }
      setModalOpen(false);
    } catch (err) {
      setSubmitError(extractApiErrorMessage(err, 'Could not save this record.'));
    }
  };

  const onDelete = async (record: PipelineRecord) => {
    setDeletingId(record.id);
    try {
      await deleteRecord(record.id).unwrap();
      toast.success(`Removed ${record.name}.`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not delete this record.'));
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Sales pipeline"
        description="Every deal in motion grouped by stage."
        actions={
          <Button size="sm" onClick={openCreate}>
            <Plus className="h-4 w-4" /> New record
          </Button>
        }
      />

      <OwnerQueryState isLoading={isLoading} error={error}>
        <OwnerLivePipelineBoard
          records={records}
          onEdit={openEdit}
          onDelete={onDelete}
          deletingId={deletingId}
        />
      </OwnerQueryState>

      <OwnerPipelineFormModal
        open={modalOpen}
        record={editing}
        isSaving={isCreating || isUpdating}
        errorMessage={submitError}
        onClose={() => setModalOpen(false)}
        onSubmit={onSubmit}
      />
    </div>
  );
}
