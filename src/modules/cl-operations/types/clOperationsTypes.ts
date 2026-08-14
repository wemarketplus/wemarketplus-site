export interface ClOperationsUiState {
  view:
    | 'communities'
    | 'inventory'
    | 'make-ready'
    // The make-ready board narrowed to the HOUSEKEEPING category — the guide's
    // "Make-Ready Clean … specifically which units are in the move-in prep
    // pipeline". Its own view rather than a filter chip on 'make-ready' because it
    // is a distinct sidebar destination for a distinct role.
    | 'make-ready-clean'
    | 'maintenance'
    | 'housekeeping'
    | 'unit-status'
    | 'maintenance-view';
}
