import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Role } from '@/shared/rbac';
import { Button, Input, Label, PasswordInput, Select } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { ASSIGNABLE_ROLE_OPTIONS } from '../constants/usersConstants';
import { newUserSchema, type NewUserFormValues } from '../schema/usersSchema';
import type { AddUserModalProps } from '../types/usersTypes';
import { generateTempPassword } from '../utils/tempPassword';

const DEFAULT_VALUES: NewUserFormValues = {
  firstName: '',
  lastName: '',
  email: '',
  role: Role.Marketer,
  password: '',
  sendInvite: true,
};

// Add User modal — presentational. The page owns useAddUser and passes the
// open/saving/error state plus the submit handler down.
export function AddUserModal({
  open,
  isSaving,
  submitError,
  onClose,
  onSubmit: submit,
}: AddUserModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    setValue,
    formState: { errors },
  } = useForm<NewUserFormValues>({
    resolver: zodResolver(newUserSchema),
    defaultValues: DEFAULT_VALUES,
  });

  const close = () => {
    reset();
    onClose();
  };

  const onSubmit = async (values: NewUserFormValues) => {
    const ok = await submit(values);
    if (ok) reset();
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title="Add User"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit(onSubmit)} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Save User'}
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
          <Label htmlFor="au-first-name">First name</Label>
          <Input id="au-first-name" autoComplete="off" {...register('firstName')} />
          {errors.firstName && (
            <p className="mt-1 text-[12px] text-destructive">{errors.firstName.message}</p>
          )}
        </div>
        <div>
          <Label htmlFor="au-last-name">Last name</Label>
          <Input id="au-last-name" autoComplete="off" {...register('lastName')} />
          {errors.lastName && (
            <p className="mt-1 text-[12px] text-destructive">{errors.lastName.message}</p>
          )}
        </div>
        <div>
          <Label htmlFor="au-email">Email</Label>
          <Input id="au-email" type="email" autoComplete="off" {...register('email')} />
          {errors.email && (
            <p className="mt-1 text-[12px] text-destructive">{errors.email.message}</p>
          )}
        </div>
        <div>
          <Label htmlFor="au-role">Role</Label>
          <Select id="au-role" {...register('role')}>
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
        <div className="sm:col-span-2">
          <div className="flex items-center justify-between">
            <Label htmlFor="au-password">Temporary password</Label>
            <button
              type="button"
              onClick={() =>
                setValue('password', generateTempPassword(), {
                  shouldValidate: true,
                  shouldDirty: true,
                })
              }
              className="text-[12px] font-semibold text-primary transition-colors hover:text-foreground"
            >
              Generate
            </button>
          </div>
          <PasswordInput id="au-password" autoComplete="new-password" {...register('password')} />
          {errors.password && (
            <p className="mt-1 text-[12px] text-destructive">{errors.password.message}</p>
          )}
        </div>
        <label className="flex items-start gap-3 text-sm text-foreground sm:col-span-2">
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4 rounded border border-white/15 bg-surface-raised text-primary focus:ring-primary/50"
            {...register('sendInvite')}
          />
          <span>Email an invite so they can set their own password</span>
        </label>
      </form>
    </Modal>
  );
}
