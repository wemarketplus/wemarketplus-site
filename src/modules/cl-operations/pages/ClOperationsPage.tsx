import { useMemo } from 'react';
import { Search } from 'lucide-react';
import {
  useRole,
  CL_INVENTORY_ROLES,
  CL_MAKE_READY_ROLES,
  CL_MAINTENANCE_ROLES,
  CL_HOUSEKEEPING_ROLES,
} from '@/shared/rbac';
import { Input } from '@/shared/ui/core';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { useOperationsView } from '../hooks/useOperationsView';
import { useOpsResource } from '../hooks/useOpsResource';
import { useCommunities } from '../hooks/useCommunities';
import { CommunitiesTable } from '../components/CommunitiesTable';
import { CommunityFormModal } from '../components/CommunityFormModal';
import {
  useListClApartmentsQuery,
  useCreateClApartmentMutation,
  useUpdateClApartmentMutation,
  useDeleteClApartmentMutation,
  useListClCommunitiesQuery,
  useListClMakeReadyQuery,
  useCreateClMakeReadyMutation,
  useUpdateClMakeReadyMutation,
  useDeleteClMakeReadyMutation,
  useListClMaintenanceQuery,
  useCreateClMaintenanceMutation,
  useUpdateClMaintenanceMutation,
  useDeleteClMaintenanceMutation,
  useListClHousekeepingQuery,
  useCreateClHousekeepingMutation,
  useUpdateClHousekeepingMutation,
  useDeleteClHousekeepingMutation,
} from '../api/clOperationsApi';
import {
  APARTMENT_STATUS_OPTIONS,
  CL_OPS_PAGE_SIZE,
  HOUSEKEEPING_STATUS_OPTIONS,
  MAINTENANCE_STATUS_OPTIONS,
  MAKE_READY_STATUS_OPTIONS,
} from '../constants/clOperationsConstants';
import {
  toApartment,
  toCreateApartment,
  toCreateHousekeeping,
  toCreateMaintenance,
  toCreateMakeReady,
} from '../utils/clOperationsMappers';
import { OperationsViewNav } from '../components/OperationsViewNav';
import { OpsFilters } from '../components/OpsFilters';
import { OccupancyHero } from '../components/OccupancyHero';
import { ApartmentsTable } from '../components/ApartmentsTable';
import { ApartmentFormModal } from '../components/ApartmentFormModal';
import { MakeReadyTable } from '../components/MakeReadyTable';
import { MakeReadyFormModal } from '../components/MakeReadyFormModal';
import { MaintenanceTable } from '../components/MaintenanceTable';
import { MaintenanceFormModal } from '../components/MaintenanceFormModal';
import { HousekeepingTable } from '../components/HousekeepingTable';
import { HousekeepingFormModal } from '../components/HousekeepingFormModal';

const HEADER = {
  inventory: 'Apartment inventory',
  'make-ready': 'Make-ready board',
  maintenance: 'Maintenance tickets',
  housekeeping: 'Housekeeping tasks',
  'unit-status': 'Unit Status',
  'maintenance-view': 'Maintenance View',
} as const;

export function ClOperationsPage() {
  const { view, changeView } = useOperationsView();
  const { isAny } = useRole();
  // Per-view edit permission, mirroring the resource's role group (communities
  // share apartment inventory's group). "Unit Status" / "Maintenance View" are
  // always read-only, regardless of role.
  const canEdit =
    view === 'communities' || view === 'inventory'
      ? isAny(CL_INVENTORY_ROLES)
      : view === 'make-ready'
        ? isAny(CL_MAKE_READY_ROLES)
        : view === 'maintenance'
          ? isAny(CL_MAINTENANCE_ROLES)
          : view === 'housekeeping'
            ? isAny(CL_HOUSEKEEPING_ROLES)
            : false;

  // Pickers: communities (for apartments) + apartments (for make-ready).
  const { data: communitiesData } = useListClCommunitiesQuery({ page: 1, limit: 100 });
  const communityOptions = useMemo(
    () => (communitiesData?.data ?? []).map((c) => ({ value: c.id, label: c.name })),
    [communitiesData],
  );
  const { data: allApartmentsData } = useListClApartmentsQuery({ page: 1, limit: 200 });
  const apartmentOptions = useMemo(
    () =>
      (allApartmentsData?.data ?? []).map((a) => ({
        value: a.id,
        label: `Unit ${a.unitNumber}`,
      })),
    [allApartmentsData],
  );
  const unitLabel = useMemo(() => {
    const map = new Map(apartmentOptions.map((o) => [o.value, o.label]));
    return (id: string | null) => (id ? (map.get(id) ?? 'Unit') : '—');
  }, [apartmentOptions]);

  // --- one resource controller per view -----------------------------------
  const [createApt, aptC] = useCreateClApartmentMutation();
  const [updateApt, aptU] = useUpdateClApartmentMutation();
  const [deleteApt, aptD] = useDeleteClApartmentMutation();
  const apartments = useOpsResource({
    noun: 'unit',
    pageSize: CL_OPS_PAGE_SIZE,
    useListQuery: useListClApartmentsQuery,
    create: createApt,
    createState: aptC,
    update: updateApt,
    updateState: aptU,
    remove: deleteApt,
    removeState: aptD,
    toCreate: toCreateApartment,
    toUpdate: toCreateApartment,
    labelOf: (a) => `unit ${a.unitNumber}`,
  });

  const [createMr, mrC] = useCreateClMakeReadyMutation();
  const [updateMr, mrU] = useUpdateClMakeReadyMutation();
  const [deleteMr, mrD] = useDeleteClMakeReadyMutation();
  const makeReady = useOpsResource({
    noun: 'make-ready task',
    pageSize: CL_OPS_PAGE_SIZE,
    useListQuery: useListClMakeReadyQuery,
    create: createMr,
    createState: mrC,
    update: updateMr,
    updateState: mrU,
    remove: deleteMr,
    removeState: mrD,
    toCreate: toCreateMakeReady,
    toUpdate: toCreateMakeReady,
    labelOf: (t) => t.taskName,
  });

  const [createMt, mtC] = useCreateClMaintenanceMutation();
  const [updateMt, mtU] = useUpdateClMaintenanceMutation();
  const [deleteMt, mtD] = useDeleteClMaintenanceMutation();
  const maintenance = useOpsResource({
    noun: 'ticket',
    pageSize: CL_OPS_PAGE_SIZE,
    useListQuery: useListClMaintenanceQuery,
    create: createMt,
    createState: mtC,
    update: updateMt,
    updateState: mtU,
    remove: deleteMt,
    removeState: mtD,
    toCreate: toCreateMaintenance,
    toUpdate: toCreateMaintenance,
    labelOf: (t) => t.ticketNumber ?? t.issue,
  });

  const [createHk, hkC] = useCreateClHousekeepingMutation();
  const [updateHk, hkU] = useUpdateClHousekeepingMutation();
  const [deleteHk, hkD] = useDeleteClHousekeepingMutation();
  const housekeeping = useOpsResource({
    noun: 'task',
    pageSize: CL_OPS_PAGE_SIZE,
    useListQuery: useListClHousekeepingQuery,
    create: createHk,
    createState: hkC,
    update: updateHk,
    updateState: hkU,
    remove: deleteHk,
    removeState: hkD,
    toCreate: toCreateHousekeeping,
    toUpdate: toCreateHousekeeping,
    labelOf: (t) => t.taskType,
  });

  // Communities view is rendered by its own branch below (a community has no
  // status field, so it doesn't fit the status-based `active` machinery).
  const communities = useCommunities();

  const active =
    view === 'inventory' || view === 'unit-status'
      ? apartments
      : view === 'make-ready'
        ? makeReady
        : view === 'maintenance' || view === 'maintenance-view'
          ? maintenance
          : housekeeping;

  const statusOptions =
    view === 'inventory' || view === 'unit-status'
      ? APARTMENT_STATUS_OPTIONS
      : view === 'make-ready'
        ? MAKE_READY_STATUS_OPTIONS
        : view === 'maintenance' || view === 'maintenance-view'
          ? MAINTENANCE_STATUS_OPTIONS
          : HOUSEKEEPING_STATUS_OPTIONS;

  const addLabel =
    view === 'inventory'
      ? 'Add Unit'
      : view === 'make-ready'
        ? 'Add Task'
        : view === 'maintenance'
          ? 'New Ticket'
          : view === 'housekeeping'
            ? 'Assign Task'
            : '';

  // Occupancy summary above the inventory / unit-status tables.
  const occupancyApartments = useMemo(
    () =>
      view === 'inventory' || view === 'unit-status' ? apartments.rows.map(toApartment) : [],
    [view, apartments.rows],
  );

  if (view === 'communities') {
    return (
      <EntityListPage
        title="Communities"
        subtitle={`${communities.total} communities`}
        addLabel="Add Community"
        onAdd={canEdit ? communities.crud.openCreate : undefined}
        isLoading={communities.isLoading}
        error={communities.error}
        errorFallback="Failed to load communities"
        filters={
          <div className="space-y-4">
            <OperationsViewNav view={view} onViewChange={changeView} />
            <div className="relative sm:max-w-sm">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <Input
                value={communities.search}
                onChange={(e) => communities.setSearch(e.target.value)}
                placeholder="Search communities…"
                className="pl-9"
                aria-label="Search communities"
              />
            </div>
          </div>
        }
        pagination={
          <EntityPagination
            page={communities.page}
            lastPage={communities.lastPage}
            isFetching={communities.isFetching}
            onPrev={communities.prevPage}
            onNext={communities.nextPage}
          />
        }
      >
        <CommunitiesTable
          communities={communities.rows}
          isMutating={communities.isMutating}
          hasFilters={communities.hasFilters}
          onEdit={communities.crud.openEdit}
          onDelete={communities.crud.confirmDelete}
          onAdd={canEdit ? communities.crud.openCreate : undefined}
        />
        <CommunityFormModal
          open={communities.crud.createOpen || communities.crud.editing !== null}
          isSaving={communities.crud.isSaving}
          editing={communities.crud.editing}
          onClose={communities.crud.editing ? communities.crud.closeEdit : communities.crud.closeCreate}
          onSubmit={communities.submit}
        />
      </EntityListPage>
    );
  }

  return (
    <EntityListPage
      title={HEADER[view]}
      subtitle={`${active.total} records`}
      addLabel={addLabel}
      onAdd={canEdit ? active.crud.openCreate : undefined}
      isLoading={active.isLoading}
      error={active.error}
      errorFallback="Failed to load operations data"
      filters={
        <div className="space-y-4">
          <OperationsViewNav view={view} onViewChange={changeView} />
          {(view === 'inventory' || view === 'unit-status') && (
            <OccupancyHero apartments={occupancyApartments} />
          )}
          <OpsFilters
            search={active.search}
            status={active.status}
            statusOptions={statusOptions}
            onSearch={active.setSearch}
            onStatus={active.setStatus}
          />
        </div>
      }
      pagination={
        <EntityPagination
          page={active.page}
          lastPage={active.lastPage}
          isFetching={active.isFetching}
          onPrev={active.prevPage}
          onNext={active.nextPage}
        />
      }
    >
      {view === 'inventory' && (
        <>
          <ApartmentsTable
            apartments={apartments.rows}
            isMutating={apartments.isMutating}
            hasFilters={apartments.hasFilters}
            onEdit={apartments.crud.openEdit}
            onDelete={apartments.crud.confirmDelete}
            onStatusChange={apartments.changeStatus}
            onAdd={canEdit ? apartments.crud.openCreate : undefined}
          />
          <ApartmentFormModal
            open={apartments.crud.createOpen || apartments.crud.editing !== null}
            isSaving={apartments.crud.isSaving}
            editing={apartments.crud.editing}
            communityOptions={communityOptions}
            onClose={apartments.crud.editing ? apartments.crud.closeEdit : apartments.crud.closeCreate}
            onSubmit={apartments.submit}
          />
        </>
      )}

      {view === 'make-ready' && (
        <>
          <MakeReadyTable
            tasks={makeReady.rows}
            unitLabel={unitLabel}
            isMutating={makeReady.isMutating}
            hasFilters={makeReady.hasFilters}
            onEdit={makeReady.crud.openEdit}
            onDelete={makeReady.crud.confirmDelete}
            onStatusChange={makeReady.changeStatus}
            onAdd={canEdit ? makeReady.crud.openCreate : undefined}
          />
          <MakeReadyFormModal
            open={makeReady.crud.createOpen || makeReady.crud.editing !== null}
            isSaving={makeReady.crud.isSaving}
            editing={makeReady.crud.editing}
            apartmentOptions={apartmentOptions}
            onClose={makeReady.crud.editing ? makeReady.crud.closeEdit : makeReady.crud.closeCreate}
            onSubmit={makeReady.submit}
          />
        </>
      )}

      {view === 'maintenance' && (
        <>
          <MaintenanceTable
            tickets={maintenance.rows}
            isMutating={maintenance.isMutating}
            hasFilters={maintenance.hasFilters}
            onEdit={maintenance.crud.openEdit}
            onDelete={maintenance.crud.confirmDelete}
            onStatusChange={maintenance.changeStatus}
            onAdd={canEdit ? maintenance.crud.openCreate : undefined}
          />
          <MaintenanceFormModal
            open={maintenance.crud.createOpen || maintenance.crud.editing !== null}
            isSaving={maintenance.crud.isSaving}
            editing={maintenance.crud.editing}
            onClose={maintenance.crud.editing ? maintenance.crud.closeEdit : maintenance.crud.closeCreate}
            onSubmit={maintenance.submit}
          />
        </>
      )}

      {view === 'housekeeping' && (
        <>
          <HousekeepingTable
            tasks={housekeeping.rows}
            isMutating={housekeeping.isMutating}
            hasFilters={housekeeping.hasFilters}
            onEdit={housekeeping.crud.openEdit}
            onDelete={housekeeping.crud.confirmDelete}
            onStatusChange={housekeeping.changeStatus}
            onAdd={canEdit ? housekeeping.crud.openCreate : undefined}
          />
          <HousekeepingFormModal
            open={housekeeping.crud.createOpen || housekeeping.crud.editing !== null}
            isSaving={housekeeping.crud.isSaving}
            editing={housekeeping.crud.editing}
            onClose={housekeeping.crud.editing ? housekeeping.crud.closeEdit : housekeeping.crud.closeCreate}
            onSubmit={housekeeping.submit}
          />
        </>
      )}

      {/* Max-tier-only read-only surfaces for the field roles — no form
          modals, no mutations, just the data. */}
      {view === 'unit-status' && (
        <ApartmentsTable
          apartments={apartments.rows}
          isMutating={apartments.isMutating}
          hasFilters={apartments.hasFilters}
          readOnly
        />
      )}

      {view === 'maintenance-view' && (
        <MaintenanceTable
          tickets={maintenance.rows}
          isMutating={maintenance.isMutating}
          hasFilters={maintenance.hasFilters}
          readOnly
        />
      )}
    </EntityListPage>
  );
}
