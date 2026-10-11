const { vrfProve, vrfVerify, plotRegisterMessage, signMessage, verifySignature, pubkeyToAddress, safeInt } = require('./crypto');
const isMerkleRoot = (v) => typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v);

const MAX_PLOT_GB = 10240;

function makeLocalAnnouncement(plot, cfg, vrfOverrides = null) {
  const miner = String(plot.miner || '').toLowerCase();
  const merkleRoot = String(plot.merkle_root || '');
  const publicKey = String(plot.public_key || cfg.minerPublicKey || '');
  if (!publicKey) return null;
  try {
    const { pubkeyToAddress } = require('./crypto');
    if (pubkeyToAddress(publicKey).toLowerCase() !== miner) return null;
  } catch { return null; }
  const privateKey = String(plot.private_key !== undefined ? plot.private_key : (cfg.minerPrivateKey || ''));
  const sizeGb = plot.size_gb;
  const totalScoops = safeInt(plot.total_scoops, 0) || 0;

  let vrfPublicKey = plot.vrf_public_key || '';
  let vrfOutput = plot.vrf_output || '';
  let vrfProof = plot.vrf_proof || '';
  if (vrfOverrides && vrfOverrides.public_key) {
    vrfPublicKey = vrfOverrides.public_key;
    vrfOutput = vrfOverrides.output;
    vrfProof = vrfOverrides.proof;
  } else if (privateKey && merkleRoot && !vrfPublicKey) {
    try {
      const vrf = vrfProve(privateKey, plot.plot_id, merkleRoot);
      vrfPublicKey = vrf.public_key;
      vrfOutput = vrf.output;
      vrfProof = vrf.proof;
    } catch { /* leave empty, will be skipped by verifiers */ }
  }

  const ann = {
    miner,
    plot_id: String(plot.plot_id || ''),
    merkle_root: merkleRoot,
    size_gb: sizeGb,
    total_scoops: totalScoops,
    vrf_public_key: vrfPublicKey,
    vrf_output: vrfOutput,
    vrf_proof: vrfProof,
    public_key: publicKey,
    node_url: cfg.nodeUrl || '',
  };
  if (plot.signature) {
    ann.signature = String(plot.signature);
  } else if (publicKey) {
    try {
      ann.signature = signMessage(plotRegisterMessage(miner, ann.plot_id, merkleRoot, String(sizeGb), String(totalScoops)), privateKey || '');
    } catch { ann.signature = ''; }
  }
  return ann;
}

function verifyAnnouncement(ann, opts = {}) {
  const requireVrf = opts.requireVrf !== false;
  const requireSig = opts.requireSig !== false;
  if (!ann || typeof ann !== 'object') return { ok: false, motivo: 'invalid announcement' };
  if (!ann.plot_id || !ann.miner) return { ok: false, motivo: 'plot_id and miner required' };
  if (!isMerkleRoot(ann.merkle_root)) return { ok: false, motivo: 'invalid merkle_root' };
  const miner = String(ann.miner).toLowerCase();
  const publicKey = String(ann.public_key || '');
  const merkleRoot = String(ann.merkle_root);
  const sizeGb = parseFloat(ann.size_gb);
  if (!Number.isFinite(sizeGb) || sizeGb <= 0) return { ok: false, motivo: 'invalid size_gb' };

  if (requireSig) {
    if (!publicKey) return { ok: false, motivo: 'public_key required for signature check' };
    try {
      if (pubkeyToAddress(publicKey).toLowerCase() !== miner) return { ok: false, motivo: 'address does not match public key' };
    } catch { return { ok: false, motivo: 'invalid miner public key' }; }
    if (!ann.signature) return { ok: false, motivo: 'missing capacity signature' };
    const msg = plotRegisterMessage(miner, String(ann.plot_id), merkleRoot, String(sizeGb), String(safeInt(ann.total_scoops, 0) || 0));
    if (!verifySignature(msg, ann.signature, publicKey)) return { ok: false, motivo: 'invalid capacity signature' };
  }

  if (requireVrf) {
    if (!ann.vrf_public_key || !ann.vrf_output || !ann.vrf_proof) return { ok: false, motivo: 'missing VRF commitment' };
    const ok = vrfVerify(String(ann.vrf_public_key), merkleRoot, String(ann.vrf_output), ann.vrf_proof);
    if (!ok) return { ok: false, motivo: 'VRF capacity proof failed' };
  }

  return { ok: true };
}

module.exports = { makeLocalAnnouncement, verifyAnnouncement, isMerkleRoot, MAX_PLOT_GB };
