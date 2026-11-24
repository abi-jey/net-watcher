import { Fragment, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import {
  allOf, alternatives, anyOf, conditions, describe, eventTypes, field as fieldInfo, fields, format, hiddenTypes, isSimple, negate, opLabel, opsFor,
  toggleType, tryParse, type Compare, type Op, type Term,
} from '../lib/filter.ts';
import { eventLabel, family } from '../lib/network.ts';
import { Icon } from './icons.tsx';
import { WindowSelect } from './ui.tsx';

/** Known values per field, offered while typing a value. */
export type Suggestions = Record<string, string[]>;

const examples: [string, string][] = [
  ['src.kind != pod and dst.kind = node', 'not from a pod, to a node'],
  ['ns = (kube-system, monitoring) and port != 53', 'two namespaces, without DNS'],
  ['domain = google.com or domain ~ facebook', 'one domain and its subdomains, or any name containing a word'],
  ['ip = 100.64.0.0/10 and not iface.type = tailscale', 'tailnet addresses seen outside the Tailscale interface'],
  ['process = curl or (process.side = none and dst.port = 443)', 'curl, or HTTPS no process was found for'],
  ['bytes > 10M', 'connections that moved more than 10 MiB'],
];

/**
 * The events search: a filter expression to type, the same filter as
 * conditions to add, negate, join with "or" and remove, and event type
 * toggles. Every change produces new expression text.
 */
export function FilterBar({ text, window, onApply, suggestions, busy, serverError }: {
  text: string; window: string; onApply: (text: string, window: string) => void; suggestions: Suggestions; busy: boolean;
  /** The server's objection to the applied filter, such as a value that is not a port. */
  serverError?: string;
}) {
  const [draft, setDraft] = useState(text);
  const [draftWindow, setDraftWindow] = useState(window);
  const [builder, setBuilder] = useState<{ at?: [number, number]; term?: Compare }>();
  const [help, setHelp] = useState(false);
  useEffect(() => { setDraft(text); setDraftWindow(window); }, [text, window]);

  const applied = useMemo(() => tryParse(text).term, [text]);
  const parsed = useMemo(() => tryParse(draft), [draft]);
  const terms = conditions(applied);
  const types = hiddenTypes(applied);
  const apply = (term: Term | null) => onApply(format(term), draftWindow);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (parsed.error) return;
    onApply(format(parsed.term), draftWindow);
  };
  const replace = (i: number, j: number, next: Term | null) => {
    const alts = alternatives(terms[i]).flatMap((alt, k) => (k === j ? (next ? [next] : []) : [alt]));
    apply(allOf(terms.flatMap((term, k) => (k === i ? (alts.length ? [anyOf(alts)] : []) : [term]))));
  };
  // "and" between two conditions becomes "or": either may hold.
  const joinOr = (i: number) => apply(allOf([...terms.slice(0, i), anyOf([...alternatives(terms[i]), ...alternatives(terms[i + 1])]), ...terms.slice(i + 2)]));
  // "or" inside a condition becomes "and": both parts must hold.
  const split = (i: number, j: number) => {
    const alts = alternatives(terms[i]);
    apply(allOf([...terms.slice(0, i), anyOf(alts.slice(0, j)), anyOf(alts.slice(j)), ...terms.slice(i + 1)]));
  };
  const save = (term: Compare) => {
    if (builder?.at) replace(builder.at[0], builder.at[1], term);
    else apply(allOf([...terms, term]));
    setBuilder(undefined);
  };

  return (
    <form className="card filter-bar" onSubmit={submit}>
      <div className="filter-row">
        <label className="field grow filter-input">
          <span>Filter <button type="button" className="link small" onClick={() => setHelp(open => !open)} aria-expanded={help}>{help ? 'hide syntax' : 'syntax'}</button></span>
          <input type="search" value={draft} spellCheck={false} onChange={event => setDraft(event.target.value)} aria-invalid={Boolean(parsed.error)}
            placeholder="e.g. src.kind != pod and (dst.kind = node or port = 53), or any text" className="mono" />
        </label>
        <label className="field">Window<WindowSelect value={draftWindow} onChange={value => { setDraftWindow(value); if (!parsed.error) onApply(format(parsed.term), value); }} /></label>
        <button className="primary" type="submit" disabled={busy || Boolean(parsed.error)}>Search</button>
      </div>
      {parsed.error && (
        <p className="filter-error" role="alert">
          <span className="mono">{draft.slice(0, parsed.error.pos)}<mark>{draft.slice(parsed.error.pos, parsed.error.pos + 1) || ' '}</mark></span> {parsed.error.message}
        </p>
      )}
      {!parsed.error && serverError && draft === text && <p className="filter-error" role="alert">{serverError}</p>}
      {help && <SyntaxHelp onExample={example => { setDraft(example); onApply(example, draftWindow); }} />}

      <div className="conditions" aria-label="Conditions; all must hold">
        {terms.map((term, i) => (
          <Fragment key={`${i}:${format(term)}`}>
            {i > 0 && <button type="button" className="joiner" onClick={() => joinOr(i - 1)} title="Both must hold. Select to accept either instead (or).">and</button>}
            <span className={`condition-group ${term.kind === 'or' ? 'any' : ''}`}>
              {alternatives(term).map((alt, j) => (
                <Fragment key={j}>
                  {j > 0 && <button type="button" className="joiner or" onClick={() => split(i, j)} title="Either may hold. Select to require both instead (and).">or</button>}
                  <Condition term={alt} onRemove={() => replace(i, j, null)} onNegate={() => replace(i, j, negate(alt))}
                    onEdit={alt.kind === 'compare' ? () => setBuilder({ at: [i, j], term: alt }) : undefined} />
                </Fragment>
              ))}
            </span>
          </Fragment>
        ))}
        <button type="button" className="add-condition" onClick={() => setBuilder(open => (open && !open.at ? undefined : {}))} aria-expanded={Boolean(builder && !builder.at)}>
          <Icon name="plus" size={12} />{terms.length ? 'and…' : 'Add condition'}
        </button>
        {terms.length > 0 && <button type="button" className="ghost small" onClick={() => apply(null)}>Clear</button>}
        {!terms.length && <span className="muted small">Showing every event. Add conditions, or type a filter above.</span>}
      </div>
      {builder && <Builder key={builder.at?.join() ?? 'new'} initial={builder.term} suggestions={suggestions} onSave={save} onCancel={() => setBuilder(undefined)} />}

      <div className="chips type-toggles" role="group" aria-label="Event types shown">
        {eventTypes.map(type => {
          const shown = !types || !types.hidden.includes(type);
          return (
            <button key={type} type="button" className="chip" aria-pressed={shown} disabled={!types} onClick={() => apply(toggleType(applied, type))}
              title={!types ? 'The filter decides types in a combined condition; edit it as text' : shown ? `Showing ${type}; select to hide` : `Hiding ${type}; select to show`}>
              <span className={`swatch ${family(type)}`} />{eventLabel(type)}
            </button>
          );
        })}
        {types && types.hidden.length > 0 && <button type="button" className="ghost small" onClick={() => apply(allOf(terms.filter((_, k) => k !== types.index)))}>Show all types</button>}
      </div>
    </form>
  );
}

function Condition({ term, onRemove, onNegate, onEdit }: { term: Term; onRemove: () => void; onNegate: () => void; onEdit?: () => void }) {
  if (!isSimple(term)) {
    return (
      <span className="condition complex">
        <span className="mono" title="A combined condition; edit it in the filter text">{format(term)}</span>
        <button type="button" className="condition-remove" onClick={onRemove} aria-label={`Remove ${format(term)}`}><Icon name="close" size={10} /></button>
      </span>
    );
  }
  const reading = describe(term);
  const negative = reading.op.startsWith('not') || reading.op === 'is not' || reading.op === 'does not contain';
  return (
    <span className={`condition ${negative ? 'negative' : ''}`}>
      <button type="button" className="condition-body" onClick={onEdit} disabled={!onEdit} title={onEdit ? 'Edit' : format(term)}>
        <span className="condition-field">{reading.field}</span>
      </button>
      <button type="button" className="condition-op" onClick={onNegate} title="Select to negate">{reading.op}</button>
      <button type="button" className="condition-body" onClick={onEdit} disabled={!onEdit} title={onEdit ? 'Edit' : format(term)}>
        <span className="condition-values">{reading.values.map((value, i) => <Fragment key={i}>{i > 0 && <span className="muted"> or </span>}<b>{value}</b></Fragment>)}</span>
      </button>
      <button type="button" className="condition-remove" onClick={onRemove} aria-label={`Remove ${reading.field} ${reading.op} ${reading.values.join(', ')}`}><Icon name="close" size={10} /></button>
    </span>
  );
}

const groups = [...new Set(fields.map(f => f.group))];

/** Picks a field, a comparison and values for one condition. */
function Builder({ initial, suggestions, onSave, onCancel }: { initial?: Compare; suggestions: Suggestions; onSave: (term: Compare) => void; onCancel: () => void }) {
  const [name, setName] = useState(initial?.field ?? 'ns');
  const [op, setOp] = useState<Op>(initial?.op ?? '=');
  const [values, setValues] = useState<string[]>(initial?.values ?? []);
  const [text, setText] = useState((initial?.values ?? []).join(', '));
  const first = useRef<HTMLSelectElement>(null);
  useEffect(() => first.current?.focus(), []);
  const info = fieldInfo(name)!;
  const ops = opsFor(info.kind);
  const choice = info.kind === 'enum' || info.kind === 'role';
  const typed = text.split(',').map(value => value.trim()).filter(Boolean);
  const chosen = choice ? values : typed;
  const single = op === '<' || op === '<=' || op === '>' || op === '>=';
  const valid = chosen.length > 0 && (!single || chosen.length === 1);
  const pickField = (next: string) => {
    setName(next);
    const kind = fieldInfo(next)!.kind;
    if (!opsFor(kind).includes(op)) setOp('=');
    setValues([]);
    if (kind === 'enum' || kind === 'role') setText('');
  };
  const listId = `values-${name}`;
  return (
    <div className="builder" role="group" aria-label={initial ? 'Edit condition' : 'Add condition'} onKeyDown={event => { if (event.key === 'Escape') onCancel(); }}>
      <label className="field">Field
        <select ref={first} value={name} onChange={event => pickField(event.target.value)}>
          {groups.map(group => (
            <optgroup key={group} label={group}>
              {fields.filter(f => f.group === group).map(f => <option key={f.name} value={f.name}>{f.label}</option>)}
            </optgroup>
          ))}
        </select>
      </label>
      <label className="field">Condition
        <select value={op} onChange={event => setOp(event.target.value as Op)}>
          {ops.map(o => <option key={o} value={o}>{opLabel(o)}</option>)}
        </select>
      </label>
      {choice ? (
        <fieldset className="field builder-choices"><legend>Any of</legend>
          {info.values!.map(option => (
            <label key={option.id} className="check">
              <input type="checkbox" checked={values.includes(option.id)} onChange={event => setValues(current => (event.target.checked ? [...current, option.id] : current.filter(v => v !== option.id)))} />
              {option.label}
            </label>
          ))}
        </fieldset>
      ) : (
        <label className="field grow">{single ? 'Value' : 'Values (comma for any of several)'}
          <input value={text} onChange={event => setText(event.target.value)} list={listId} spellCheck={false} className="mono"
            onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); if (valid) onSave({ kind: 'compare', field: name, op, values: chosen }); } }}
            placeholder={info.kind === 'ip' ? '10.0.0.7, 100.64.0.0/10' : info.kind === 'number' ? '443, 1000-2000' : op === '~' || op === '!~' ? 'part of a value' : 'none for unset'} />
          <datalist id={listId}>{(suggestions[name] ?? suggestions[name.replace(/^(src|dst)\./, '')] ?? []).map(value => <option key={value} value={value} />)}</datalist>
        </label>
      )}
      <p className="muted small builder-help">{info.help}</p>
      <div className="builder-actions">
        <button type="button" className="primary" disabled={!valid} onClick={() => onSave({ kind: 'compare', field: name, op, values: chosen })}>{initial ? 'Save' : 'Add'}</button>
        <button type="button" className="ghost" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

function SyntaxHelp({ onExample }: { onExample: (example: string) => void }) {
  return (
    <div className="syntax-help">
      <p>
        Conditions are <code>field op value</code>: <code>=</code> is, <code>!=</code> is not, <code>~</code> contains, <code>!~</code> does not contain,
        and <code>&lt; &lt;= &gt; &gt;=</code> for numbers. A list <code>(a, b)</code> matches any of its values; <code>none</code> matches an unset value.
        Combine with <code>and</code> (or a space), <code>or</code>, <code>not</code> and parentheses. A plain word searches addresses, names, namespaces and processes;
        <code>-word</code> excludes it.
      </p>
      <p>
        Fields without <code>src.</code>/<code>dst.</code> cover both ends: <code>kind = pod</code> means either end is a pod, and <code>kind != pod</code> means neither is.
        Addresses take prefixes such as <code>10.0.0.0/8</code>; ports and sizes take ranges such as <code>1000-2000</code> and units such as <code>1.5k</code> or <code>2s</code>.
      </p>
      <p className="fields-list">
        {fields.filter(f => !f.name.startsWith('src.') && !f.name.startsWith('dst.')).map(f => <span key={f.name} title={f.help}><code>{f.name}</code></span>)}
      </p>
      <ul className="examples">
        {examples.map(([example, meaning]) => (
          <li key={example}><button type="button" className="link mono" onClick={() => onExample(example)}>{example}</button> <span className="muted">{meaning}</span></li>
        ))}
      </ul>
    </div>
  );
}
