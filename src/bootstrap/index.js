
const { loadConfig, log } = require('../../config/config');
const { ChocoNode } = require('./node');

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  const BOLD = '\x1b[1m';
  const CYAN = '\x1b[36m';
  const GREEN = '\x1b[32m';
  const DIM = '\x1b[2m';
  const RESET = '\x1b[0m';

  console.log(`
${CYAN} ██████╗ ██████╗██████╗  ██████╗  ██████╗    ███╗   ██╗ ██████╗ ██████╗ ███████╗
██║     ██║     ██████╔╝██║   ██║██║         ██╔██╗ ██║██║   ██║██║  ██║██╔════╝
██║     ██║     ██╔═══╝ ██║   ██║██║         ██║╚██╗██║██║   ██║██║  ██║█████╗  
╚██████╗╚██████╗██║     ╚██████╔╝╚██████╗    ██║ ╚████║╚██████╔╝██████╔╝███████╗
 ╚═════╝ ╚═════╝╚═╝      ╚═════╝  ╚═════╝    ╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝${RESET}

  ${BOLD}ChocoCoin Proof-of-Capacity Node${RESET}

  ${GREEN}USAGE${RESET}
    node src/bootstrap/index.js              Start the node
    node src/bootstrap/index.js --help       Show this help

  ${GREEN}ENVIRONMENT VARIABLES${RESET}
    ${DIM}PORT${RESET}              3001                      HTTP port
    ${DIM}MINER_ADDRESS${RESET}     0x...                     Block signing address
    ${DIM}LOG_LEVEL${RESET}         info                      Log level (trace/debug/info/warn/error)
    ${DIM}DATA_DIR${RESET}          ./node-data               Data directory
    ${DIM}PLOTS_DIR${RESET}         ./plots                   Plot directory
    ${DIM}ADMIN_TOKEN${RESET}       ...                       Admin API token

  ${GREEN}CONFIG FILES${RESET}
    config/config.env               KEY=VALUE overrides
    config/node_config.json         Auto-generated, overrides defaults

  ${GREEN}EXAMPLES${RESET}
    node src/bootstrap/index.js
    PORT=3002 node src/bootstrap/index.js

  `);
  process.exit(0);
}

const cfg = loadConfig();
if (cfg.nodeUrl) log('info', `public url: ${cfg.nodeUrl}`);
const node = new ChocoNode(cfg);
node.start();
