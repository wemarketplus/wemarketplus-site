import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { Button, Input, Label, Select } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { Role } from '@/shared/rbac';
import { ASSIGNABLE_ROLE_OPTIONS, ASSIGNABLE_ROLES } from '../constants/usersConstants';
import { editUserSchema, type EditUserFormValues } from '../schema/usersSchema';
import type { EditUserModalProps } from '../types/usersTypes';

// The role <Select> only offers assignable (non-SuperAdmin) roles. A SuperAdmin
// target cannot be represented there, so seed the select with Admin; a tenant
// admin editing such a row would be blocked server-side anyway.
type AssignableRole = (typeof ASSIGNABLE_ROLES)[number];
const toAssignableRole = (role: Role): AssignableRole =>
  (ASSIGNABLE_ROLES as readonly Role[]).includes(role)
    ? (role as AssignableRole)
    : Role.Admin;

// Edit User modal — presentational. The page owns useEditUser and passes the
// target user, saving/error state, and the submit handler down. Mirrors
// AddUserModal's conventions (RHF + zod, inline error box, Modal footer).
export function EditUserModal({
  user,
  open,
  isSaving,
  submitError,
  onClose,
  onSubmit: submit,
}: EditUserModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<EditUserFormValues>({
    resolver: zodResolver(editUserSchema),
    defaultValues: {
      firstName: '',
      lastName: '',
      role: Role.Marketer,
      isActive: true,
    },
  });

  // Re-seed the form whenever the target user changes (a new row was opened).
  useEffect(() => {
    if (user) {
      reset({
        firstName: user.firstName,
        lastName: user.lastName,
        role: toAssignableRole(user.role),
        isActive: user.isActive,
      });
    }
  }, [user, reset]);

  const onSubmit = async (values: EditUserFormValues) => {
    await submit(values);
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Edit User"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit(onSubmit)} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Save changes'}
          </Button>
        </>
      }
    >
      {submitError && (
        <p className="mb-4 rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
          {submitError}
        </p>
      )}
      <form onSubmit={handleSubmit(onSubmit)} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <Label htmlFor="eu-first-name">First name</Label>
          <Input id="eu-first-name" autoComplete="off" {...register('firstName')} />
          {errors.firstName && (
            <p className="mt-1 text-[12px] text-destructive">{errors.firstName.message}</p>
          )}
        </div>
        <div>
          <Label htmlFor="eu-last-name">Last name</Label>
          <Input id="eu-last-name" autoComplete="off" {...register('lastName')} />
          {errors.lastName && (
            <p className="mt-1 text-[12px] text-destructive">{errors.lastName.message}</p>
          )}
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="eu-email">Email</Label>
          <Input id="eu-email" type="email" value={user?.email ?? ''} readOnly disabled />
        </div>
        <div>
          <Label htmlFor="eu-role">Role</Label>
          <Select id="eu-role" {...register('role')}>
            {ASSIGNABLE_ROLE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
          {errors.role && (
            <p className="mt-1 text-[12px] text-destructive">{errors.role.message}</p>
          )}
        </div>
        <label className="flex items-start gap-3 self-end text-sm text-foreground">
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4 rounded border border-border/15 bg-surface-raised text-primary focus:ring-primary/50"
            {...register('isActive')}
          />
          <span>Account active (uncheck to deactivate)</span>
        </label>
      </form>
    </Modal>
  );
}
