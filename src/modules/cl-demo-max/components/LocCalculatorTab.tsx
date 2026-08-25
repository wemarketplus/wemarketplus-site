import { useState } from 'react';
import { Card, DemoButton, Field, FI, TBL, TD, TH } from '@/shared/cl-demo';
import { LOC_SERVICES } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces rLOC(): base-rate config, a quick rate calculator, and the
// level-of-care schedule table.
export function LocCalculatorTab() {
  const { locBase, actions } = useMaxDemo();
  const [il, setIl] = useState(String(locBase.IL));
  const [al, setAl] = useState(String(locBase.AL));
  const [mc, setMc] = useState(String(locBase.MC));
  const [addon, setAddon] = useState(String(locBase.addon));
  const [care, setCare] = useState<'IL' | 'AL' | 'MC'>('IL');
  const [loc, setLoc] = useState('2');
  const [second, setSecond] = useState('0');
  const [park, setPark] = useState('0');
  const [result, setResult] = useState<{ amt: number; note: string } | null>(null);

  const saveRates = () => actions.saveLocRates({ IL: parseInt(il) || 3200, AL: parseInt(al) || 4500, MC: parseInt(mc) || 5800, addon: parseInt(addon) || 150 });

  const calc = () => {
    const bases = { IL: parseInt(il) || locBase.IL, AL: parseInt(al) || locBase.AL, MC: parseInt(mc) || locBase.MC };
    const add = parseInt(addon) || locBase.addon;
    const l = parseInt(loc) || 1;
    const sec = parseInt(second) || 0;
    const pk = parseInt(park) || 0;
    const total = bases[care] + (l - 1) * add + sec + pk;
    setResult({ amt: total, note: `${care} Level ${l}${sec ? ' + 2nd person' : ''} + $${pk} parking` });
  };

  return (
    <>
      <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
        <Card title="Base Rate Configuration" action={<DemoButton sm onClick={saveRates}>Save Rates</DemoButton>}>
          <div className="grid grid-cols-2 gap-3">
            <Field label="IL Base Rate ($/mo)"><input autoComplete="off" className={FI} type="number" value={il} onChange={(e) => setIl(e.target.value)} /></Field>
            <Field label="AL Base Rate ($/mo)"><input autoComplete="off" className={FI} type="number" value={al} onChange={(e) => setAl(e.target.value)} /></Field>
            <Field label="MC Base Rate ($/mo)"><input autoComplete="off" className={FI} type="number" value={mc} onChange={(e) => setMc(e.target.value)} /></Field>
            <Field label="LOC Add-on per Level ($)"><input autoComplete="off" className={FI} type="number" value={addon} onChange={(e) => setAddon(e.target.value)} /></Field>
          </div>
        </Card>

        <Card title="Quick Rate Calculator">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Care Level"><select autoComplete="off" className={FI} value={care} onChange={(e) => setCare(e.target.value as 'IL' | 'AL' | 'MC')}><option value="IL">Independent Living</option><option value="AL">Assisted Living</option><option value="MC">Memory Care</option></select></Field>
            <Field label="LOC Score (1–5)"><input autoComplete="off" className={FI} type="number" min={1} max={5} value={loc} onChange={(e) => setLoc(e.target.value)} /></Field>
            <Field label="Second Person?"><select autoComplete="off" className={FI} value={second} onChange={(e) => setSecond(e.target.value)}><option value="0">No</option><option value="600">Yes (+$600)</option></select></Field>
            <Field label="Parking ($/mo)"><input autoComplete="off" className={FI} type="number" value={park} onChange={(e) => setPark(e.target.value)} /></Field>
          </div>
          <DemoButton variant="g" className="mt-2" onClick={calc}>Calculate</DemoButton>
          {result && (
            <div className="mt-[14px] rounded-[10px] border border-[#4fc87a]/15 bg-[#071120] p-4">
              <div className="mb-1.5 text-[11px] font-bold uppercase text-[#4b6278]">Estimated Monthly Rate</div>
              <div className="text-[40px] font-black text-[#4fc87a]">${result.amt.toLocaleString()}</div>
              <div className="mt-1 text-[11px] text-[#6b7fa3]">{result.note}</div>
            </div>
          )}
        </Card>
      </div>

      <Card title="Level of Care Schedule">
        <div className="overflow-x-auto">
          <table className={TBL}>
            <thead>
              <tr>{['Level', 'IL Total', 'AL Total', 'MC Total', 'Services'].map((h) => <th key={h} className={TH}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {[1, 2, 3, 4, 5].map((l, i) => (
                <tr key={l} className="hover:bg-white/[0.02]">
                  <td className={`${TD} font-bold text-[#f4f8ff]`}>Level {l}</td>
                  <td className={`${TD} font-bold text-[#3d9ee8]`}>${(locBase.IL + (l - 1) * locBase.addon).toLocaleString()}</td>
                  <td className={`${TD} font-bold text-[#f59e0b]`}>${(locBase.AL + (l - 1) * locBase.addon).toLocaleString()}</td>
                  <td className={`${TD} font-bold text-[#4fc87a]`}>${(locBase.MC + (l - 1) * locBase.addon).toLocaleString()}</td>
                  <td className={`${TD} text-[11px] text-[#6b7fa3]`}>{LOC_SERVICES[i]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
