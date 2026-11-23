import { useState } from "react";
import type { Engine, VpnProfile } from "../types";
import { defaultPort, newProfile } from "../types";
import { TrustedCertManager } from "./TrustedCertManager";
import { DeleteConfirmModal } from "./DeleteConfirmModal";

interface Props {
  profile: VpnProfile | null; // null = creating new
  onSave: (profile: VpnProfile, password?: string) => Promise<void>;
  onCancel: () => void;
  onDelete?: (id: string) => Promise<void>;
  /** Abre com o foco no campo "Redes pela VPN" (atalho do alerta de full tunnel). */
  focusRoutes?: boolean;
}

export function ProfileEditor({ profile, onSave, onCancel, onDelete, focusRoutes }: Props) {
  const isNew = profile === null;
  const [form, setForm] = useState<VpnProfile>(profile ?? newProfile());
  const [dnsDomainsText, setDnsDomainsText] = useState(
    (profile?.dns_match_domains ?? []).join(", "),
  );
  const [routesText, setRoutesText] = useState((profile?.tunnel_routes ?? []).join(", "));
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  const isCheckpoint = form.engine === "checkpoint";

  // O Engine só muda na criação. A porta acompanha o padrão do Engine enquanto o usuário não a mexeu;
  // o Check Point entra sempre pelo IdP, então não leva usuário, senha nem OTP.
  const changeEngine = (engine: Engine) => {
    const patch: Partial<VpnProfile> =
      engine === "checkpoint"
        ? { auth_type: "Saml", username: null, otp_required: false }
        : { auth_type: "Password" };
    setForm({
      ...form,
      ...patch,
      engine,
      port: form.port === defaultPort(form.engine) ? defaultPort(engine) : form.port,
    });
    setPassword("");
  };

  const handleSave = async () => {
    if (!form.name.trim() || !form.host.trim()) {
      setError("Name and Host are required");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onSave(form, !isCheckpoint && password ? password : undefined);
    } catch (e) {
      setError(String(e));
      setSaving(false);
    }
  };

  const inputClass =
    "w-full bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white/90 placeholder-white/30 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/30";

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2 mb-1">
        <button
          onClick={onCancel}
          className="text-white/40 hover:text-white/80 transition-colors"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </button>
        <h2 className="text-sm font-semibold text-white/80">
          {isNew ? "New Profile" : "Edit Profile"}
        </h2>
        {!isNew && onDelete && (
          <button
            onClick={() => setShowDeleteConfirm(true)}
            className="ml-auto text-red-400 hover:text-red-300 text-xs transition-colors"
          >
            Delete
          </button>
        )}
      </div>

      {error && (
        <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">{error}</div>
      )}

      <div className="flex flex-col gap-2.5 max-h-72 overflow-y-auto pr-1">
        <div className="flex flex-col gap-1">
          <span className="text-xs text-white/40">Engine</span>
          <div className="flex gap-4">
            {(["fortinet", "checkpoint"] as const).map((engine) => (
              <label
                key={engine}
                className={`flex items-center gap-1.5 ${isNew ? "cursor-pointer" : "opacity-60"}`}
              >
                <input
                  type="radio"
                  name="engine"
                  checked={form.engine === engine}
                  disabled={!isNew}
                  onChange={() => changeEngine(engine)}
                  className="accent-blue-500"
                />
                <span className="text-sm text-white/70">
                  {engine === "fortinet" ? "Fortinet" : "Check Point"}
                </span>
              </label>
            ))}
          </div>
        </div>

        <label className="flex flex-col gap-1">
          <span className="text-xs text-white/40">Name</span>
          <input
            className={inputClass}
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="My VPN"
          />
        </label>

        <div className="grid grid-cols-3 gap-2">
          <label className="flex flex-col gap-1 col-span-2">
            <span className="text-xs text-white/40">Host</span>
            <input
              className={inputClass}
              value={form.host}
              onChange={(e) => setForm({ ...form, host: e.target.value })}
              placeholder="vpn.example.com"
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-white/40">Port</span>
            <input
              type="number"
              className={inputClass}
              value={form.port}
              onChange={(e) => setForm({ ...form, port: parseInt(e.target.value) || defaultPort(form.engine) })}
            />
          </label>
        </div>

        {isCheckpoint && (
          <span className="text-xs text-white/40">
            Signs in through your identity provider, in the browser.
          </span>
        )}

        {!isCheckpoint && (
        <div className="flex flex-col gap-1">
          <span className="text-xs text-white/40">Authentication</span>
          <div className="flex gap-4">
            <label className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="radio"
                name="auth_type"
                checked={form.auth_type === "Password"}
                onChange={() => setForm({ ...form, auth_type: "Password" })}
                className="accent-blue-500"
              />
              <span className="text-sm text-white/70">Password</span>
            </label>
            <label className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="radio"
                name="auth_type"
                checked={form.auth_type === "Saml"}
                onChange={() => setForm({ ...form, auth_type: "Saml", otp_required: false })}
                className="accent-blue-500"
              />
              <span className="text-sm text-white/70">SAML</span>
            </label>
          </div>
        </div>
        )}

        {!isCheckpoint && form.auth_type === "Password" && (
          <>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-white/40">Username</span>
              <input
                className={inputClass}
                value={form.username ?? ""}
                onChange={(e) => setForm({ ...form, username: e.target.value || null })}
                placeholder="john.doe"
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-white/40">Password</span>
              <input
                type="password"
                className={inputClass}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={isNew ? "Enter password" : "Leave empty to keep current"}
              />
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={form.otp_required}
                onChange={(e) => setForm({ ...form, otp_required: e.target.checked })}
                className="accent-blue-500"
              />
              <span className="text-sm text-white/70">Require OTP on connect</span>
            </label>
          </>
        )}

        <label className="flex flex-col gap-1">
          <span className="text-xs text-white/40">
            {isCheckpoint ? "Login option (optional)" : "Realm (optional)"}
          </span>
          <input
            className={inputClass}
            value={form.realm ?? ""}
            onChange={(e) => setForm({ ...form, realm: e.target.value || null })}
            placeholder="optional"
          />
          {isCheckpoint && (
            <span className="text-xs text-white/40">
              Leave empty when the gateway offers a single option.
            </span>
          )}
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs text-white/40">DNS domains (optional)</span>
          <input
            className={inputClass}
            value={dnsDomainsText}
            onChange={(e) => {
              setDnsDomainsText(e.target.value);
              setForm({
                ...form,
                dns_match_domains: e.target.value.split(/[,\s]+/).filter(Boolean),
              });
            }}
            placeholder="corp.example.com, intranet.local"
          />
          <span className="text-xs text-white/40">
            Only these domains use the VPN DNS; everything else keeps your normal DNS.
            Leave empty to use the gateway's DNS suffixes. In full tunnel the VPN DNS resolves
            every name, since all traffic goes through the VPN anyway.
          </span>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs text-white/40">Networks through the VPN (optional)</span>
          <input
            id="tunnel-routes"
            autoFocus={focusRoutes}
            className={inputClass}
            value={routesText}
            onChange={(e) => {
              setRoutesText(e.target.value);
              setForm({
                ...form,
                tunnel_routes: e.target.value.split(/[,\s]+/).filter(Boolean),
              });
            }}
            placeholder="10.0.0.0/8, 172.16.0.0/12"
          />
          <span className="text-xs text-white/40">
            Only these networks go through the VPN; everything else uses your normal connection,
            even if the gateway sends all traffic through it (full tunnel). Leave empty to use the
            gateway's routes. Applies on the next connection.
          </span>
        </label>

        <label className="flex items-start gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={form.ignore_cert_errors}
            onChange={(e) => setForm({ ...form, ignore_cert_errors: e.target.checked })}
            className="accent-blue-500 mt-0.5"
          />
          <span className="flex flex-col">
            <span className="text-sm text-white/70">Ignore certificate errors</span>
            <span className="text-xs text-white/40">
              Trusts whatever certificate the gateway presents. Only use on gateways you control.
            </span>
          </span>
        </label>

        <TrustedCertManager
          certs={form.trusted_certs}
          onChange={(certs) => setForm({ ...form, trusted_certs: certs })}
        />
      </div>

      <div className="flex gap-2 mt-1">
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex-1 py-2 px-4 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
        >
          {saving ? "Saving..." : "Save"}
        </button>
        <button
          onClick={onCancel}
          className="flex-1 py-2 px-4 bg-white/10 hover:bg-white/15 text-white/70 text-sm font-medium rounded-lg transition-colors"
        >
          Cancel
        </button>
      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && onDelete && (
        <DeleteConfirmModal
          profileName={form.name || "Unnamed"}
          onConfirm={() => onDelete(form.id)}
          onCancel={() => setShowDeleteConfirm(false)}
        />
      )}
    </div>
  );
}
