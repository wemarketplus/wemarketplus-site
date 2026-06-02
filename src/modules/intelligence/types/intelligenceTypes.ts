export interface IntelligenceKpi {
  id: string;
  label: string;
  value: string;
  delta?: string;
}

export interface LeaderboardRow {
  id: string;
  marketer: string;
  admissions: number;
  conversion: number;
}

export interface IntelligenceUiState {
  range: '7d' | '30d' | 'mtd';
}

export interface RangeOption {
  value: IntelligenceUiState['range'];
  label: string;
}
