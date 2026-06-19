'use client';

import type { FileScanDetail, Report, Signal, UrlScanDetail } from '@/lib/types';
import { SEVERITY, VERDICT, bar } from '@/lib/ui';

function Row({ k, v, dim }: { k: string; v: React.ReactNode; dim?: boolean }) {
  return (
    <div className="detail-row">
      <span className="text-muted">{k}</span>
      <span className={`min-w-0 break-all ${dim ? 'text-muted' : 'text-fg'}`}>{v}</span>
    </div>
  );
}

function DetailBlock({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-2 text-muted">{title}</div>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function UrlDetails({ d }: { d: UrlScanDetail }) {
  return (
    <div className="space-y-4">
      <DetailBlock title="network">
        <Row k="host" v={d.host} />
        {d.registrableDomain && <Row k="domain" v={d.registrableDomain} />}
        <Row k="resolved" v={d.resolvedIps.length ? d.resolvedIps.join(', ') : <span className="text-muted">none</span>} />
        {d.http?.status !== undefined && <Row k="http" v={`${d.http.status}${d.http.contentType ? ` / ${d.http.contentType}` : ''}`} />}
        {d.finalUrl && d.finalUrl !== d.normalized && <Row k="final" v={d.finalUrl} />}
        {d.fetchError && <Row k="fetch" v={<span style={{ color: '#fd971f' }}>{d.fetchError}</span>} />}
      </DetailBlock>

      {(d.tls || d.rdap || d.dns) && (
        <DetailBlock title="enrichment">
          {d.tls && (
            <Row
              k="tls"
              v={
                <span style={{ color: d.tls.valid ? '#a6e22e' : '#f92672' }}>
                  {d.tls.valid ? 'valid' : 'invalid'}
                  {d.tls.issuer ? <span className="text-muted"> / {d.tls.issuer}</span> : null}
                </span>
              }
            />
          )}
          {d.rdap?.ageDays != null && (
            <Row k="age" v={`${d.rdap.ageDays} days${d.rdap.registeredAt ? ` / reg. ${d.rdap.registeredAt.slice(0, 10)}` : ''}`} />
          )}
          {d.dns && <Row k="email auth" v={`spf ${d.dns.hasSpf ? 'yes' : 'no'} / dmarc ${d.dns.hasDmarc ? d.dns.dmarcPolicy ?? 'yes' : 'no'}`} />}
        </DetailBlock>
      )}

      {d.content && (
        <DetailBlock title="page content">
          <Row k="password" v={d.content.hasPasswordField ? 'yes' : 'no'} />
          {d.content.crossDomainForm && <Row k="form posts" v={<span style={{ color: '#f92672' }}>{d.content.crossDomainForm}</span>} />}
          {d.content.brandsInContent.length > 0 && <Row k="brands" v={d.content.brandsInContent.join(', ')} />}
          {d.content.obfuscation.length > 0 && <Row k="obfuscation" v={d.content.obfuscation.join(', ')} />}
        </DetailBlock>
      )}

      {d.reputation.length > 0 && (
        <DetailBlock title="reputation">
          <Row
            k="feeds"
            v={d.reputation.map((r) => `${r.provider}: ${!r.available ? 'n/a' : r.listed ? 'listed' : 'clean'}`).join(' / ')}
          />
        </DetailBlock>
      )}
    </div>
  );
}

function FileDetails({ d }: { d: FileScanDetail }) {
  return (
    <div className="space-y-4">
      <DetailBlock title="file">
        <Row k="name" v={d.filename} />
        <Row k="size" v={`${d.size.toLocaleString()} bytes`} />
        <Row k="type" v={`${d.realTypeLabel ?? d.realType ?? 'unknown'}${d.typeMismatch ? ' / extension mismatch' : ''}`} />
        <Row k="entropy" v={`${d.entropy} / 8`} />
        <Row k="sha256" v={d.sha256} dim />
      </DetailBlock>

      {(d.pe || d.yaraHits.length > 0 || d.staticFindings.length > 0) && (
        <DetailBlock title="static analysis">
          {d.pe?.imphash && <Row k="imphash" v={d.pe.imphash} dim />}
          {d.pe && (
            <Row
              k="pe"
              v={`${d.pe.importedDlls.length} imports / ${d.pe.suspiciousImports.length} suspicious / ${d.pe.signed ? 'signed' : 'unsigned'}${d.pe.packerHint ? ` / ${d.pe.packerHint}` : ''}`}
            />
          )}
          {d.yaraHits.length > 0 && <Row k="yara" v={d.yaraHits.map((h) => h.rule).join(', ')} />}
          {d.staticFindings.length > 0 && <Row k="findings" v={d.staticFindings.map((f) => f.title).join(', ')} />}
        </DetailBlock>
      )}

      {(d.vt || d.mbazaar || d.detonation) && (
        <DetailBlock title="integrations">
          {d.vt && <Row k="virustotal" v={d.vt.available ? (d.vt.listed ? 'listed' : 'clean') : 'n/a'} />}
          {d.mbazaar && <Row k="malwarebazaar" v={d.mbazaar.available ? (d.mbazaar.listed ? 'listed' : 'clean') : 'n/a'} />}
          {d.detonation && <Row k="tartarus" v={d.detonation.ran ? 'ran' : d.detonation.available ? 'available' : 'n/a'} />}
        </DetailBlock>
      )}
    </div>
  );
}

function SignalRow({ signal }: { signal: Signal }) {
  const sev = SEVERITY[signal.severity];
  return (
    <div className="signal-row">
      <div className="flex items-start gap-2">
        <span className="mt-0.5 shrink-0 tabular-nums" style={{ color: sev.hex }}>
          {sev.mark}
        </span>
        <div className="min-w-0">
          <div className="text-fg">{signal.title}</div>
          <div className="text-muted">{signal.detail}</div>
        </div>
      </div>
      <span className="signal-weight">{signal.mitigates ? 'mitigates' : signal.weight ? `w${signal.weight}` : signal.severity}</span>
    </div>
  );
}

export default function ReportCard({ report }: { report: Report }) {
  const v = VERDICT[report.verdict];
  const b = bar(report.score, 28);
  const risk = report.signals.filter((s) => !s.mitigates && s.weight > 0);
  const mitigating = report.signals.filter((s) => s.mitigates);
  const info = report.signals.filter((s) => !s.mitigates && s.weight === 0);

  return (
    <section className="text-[13px] leading-relaxed">
      <div className="break-all text-muted">
        <span className="prompt">&gt;</span> {report.target}
      </div>

      <div className="report-summary mt-4">
        <div>
          <div className="metric-label">verdict</div>
          <div className="glow text-lg font-bold tracking-wide" style={{ color: v.hex }}>
            {v.label}
          </div>
        </div>
        <div>
          <div className="metric-label">risk</div>
          <div className="tabular-nums">
            <span style={{ color: v.hex }}>{b.filled}</span>
            <span style={{ color: '#3b3d31' }}>{b.empty}</span>
            <span className="ml-2 text-fg">{report.score}</span>
            <span className="text-muted">/100</span>
          </div>
        </div>
        <div>
          <div className="metric-label">confidence</div>
          <div className="tabular-nums text-fg">{(report.confidence * 100).toFixed(0)}%</div>
        </div>
        <div>
          <div className="metric-label">runtime</div>
          <div className="tabular-nums text-fg">{report.durationMs}ms</div>
        </div>
      </div>

      <p className="mt-4 max-w-prose text-fg">{report.summary}</p>

      <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.72fr)]">
        <div className="min-w-0">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-muted">evidence</span>
            <span className="text-muted">{risk.length} risk / {mitigating.length} mitigating</span>
          </div>
          <div className="space-y-2">
            {risk.length === 0 && <div className="text-muted">No risk signals in the checks run.</div>}
            {risk.map((s) => (
              <SignalRow key={s.id} signal={s} />
            ))}
            {mitigating.map((s) => (
              <SignalRow key={s.id} signal={s} />
            ))}
            {info.map((s) => (
              <SignalRow key={s.id} signal={s} />
            ))}
          </div>
        </div>

        <div className="min-w-0 border-t border-border pt-4 xl:border-l xl:border-t-0 xl:pl-5 xl:pt-0">
          {report.detail.kind === 'url' ? <UrlDetails d={report.detail} /> : <FileDetails d={report.detail} />}
          {report.iocs.length > 0 && (
            <div className="mt-4 border-t border-border pt-4">
              <div className="mb-2 text-muted">iocs</div>
              <div className="space-y-1">
                {report.iocs.map((ioc, i) => (
                  <Row key={`${ioc.type}-${ioc.value}-${i}`} k={ioc.type} v={ioc.value} dim={ioc.type === 'sha256'} />
                ))}
              </div>
            </div>
          )}
          <div className="mt-4 border-t border-border pt-3 text-muted">
            report {report.id.slice(0, 8)} / engine v{report.engineVersion}
          </div>
        </div>
      </div>
    </section>
  );
}
