#!/usr/bin/env node
/**
 * ToolVeto Reference Good MCP Server
 * Passes all ToolVeto D1-D5 checks, 0 fatal vetoes, certified Gold/Platinum.
 */

import * as readline from 'node:readline';

const payments = new Map(); // idempotency_key -> payment
const appointments = new Map();

const tools = [
  {
    name: 'create_payment',
    description: 'Creates a financial payment transaction safely with required idempotency protection and dry-run simulation',
    isMutation: true,
    inputSchema: {
      type: 'object',
      properties: {
        amount: { type: 'number', description: 'Payment amount in base units (e.g. cents)' },
        currency: { type: 'string', description: 'ISO 4217 three-letter currency code (e.g. USD)' },
        customer_id: { type: 'string', description: 'Customer identifier UUID' },
        idempotency_key: { type: 'string', description: 'Unique UUID to guarantee idempotency and prevent double-charging on retry' },
        dry_run: { type: 'boolean', description: 'If true, validates transaction parameters without persisting charges' },
      },
      required: ['amount', 'currency', 'customer_id', 'idempotency_key'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_payment',
    description: 'Retrieves payment transaction details and verification receipt by payment_id or idempotency_key',
    isMutation: false,
    inputSchema: {
      type: 'object',
      properties: {
        payment_id: { type: 'string', description: 'Payment identifier' },
        idempotency_key: { type: 'string', description: 'Idempotency key of the transaction' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'update_appointment',
    description: 'Updates appointment reservation date with strict format validation, dry-run, and structured error feedback',
    isMutation: true,
    inputSchema: {
      type: 'object',
      properties: {
        appointment_id: { type: 'string', description: 'Unique appointment UUID' },
        date: { type: 'string', format: 'date', description: 'Appointment date in ISO format YYYY-MM-DD' },
        idempotency_key: { type: 'string', description: 'Unique request token for replay safety' },
        dry_run: { type: 'boolean', description: 'Simulates update without persisting changes' },
      },
      required: ['appointment_id', 'date'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_appointment',
    description: 'Retrieves customer appointment schedule and reservation state for verification inspection',
    isMutation: false,
    inputSchema: {
      type: 'object',
      properties: {
        appointment_id: { type: 'string', description: 'Unique appointment UUID' },
      },
      required: ['appointment_id'],
      additionalProperties: false,
    },
  },
  {
    name: 'list_invoices',
    description: 'Lists customer invoices with strict pagination controls to prevent context saturation and token budget overflow',
    isMutation: false,
    inputSchema: {
      type: 'object',
      properties: {
        customer_id: { type: 'string', description: 'Customer ID' },
        limit: { type: 'integer', description: 'Maximum number of invoices to return (default 20, max 100)' },
        cursor: { type: 'string', description: 'Opaque pagination cursor for fetching subsequent pages' },
      },
      additionalProperties: false,
    },
  },
];

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const req = JSON.parse(trimmed);
    const { id, method, params } = req;

    if (method === 'initialize') {
      sendResponse(id, {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'good-mcp-server', version: '1.0.0' },
      });
      return;
    }

    if (method === 'tools/list') {
      sendResponse(id, { tools });
      return;
    }

    if (method === 'tools/call') {
      const toolName = params?.name;
      const args = params?.arguments || {};

      if (toolName === 'create_payment') {
        const idempKey = args.idempotency_key;
        if (!idempKey) {
          sendResponse(id, {
            isError: true,
            content: [{ type: 'text', text: "Parameter 'idempotency_key' is required to prevent double-charging." }],
          });
          return;
        }

        if (args.dry_run) {
          sendResponse(id, {
            content: [{ type: 'text', text: JSON.stringify({ dry_run: true, status: 'simulated_authorized', amount: args.amount, currency: args.currency }) }],
          });
          return;
        }

        // Idempotent deduplication check
        if (payments.has(idempKey)) {
          const existing = payments.get(idempKey);
          sendResponse(id, {
            content: [{ type: 'text', text: JSON.stringify({ status: 'idempotent_cached', payment: existing }) }],
          });
          return;
        }

        const payment = {
          payment_id: `pay_static_receipt_001`,
          amount: args.amount,
          currency: args.currency,
          customer_id: args.customer_id,
          idempotency_key: idempKey,
          created_at: new Date().toISOString(),
        };
        payments.set(idempKey, payment);

        sendResponse(id, {
          content: [{ type: 'text', text: JSON.stringify({ status: 'created', payment }) }],
        });
        return;
      }

      if (toolName === 'get_payment') {
        let payment = null;
        if (args.idempotency_key && payments.has(args.idempotency_key)) {
          payment = payments.get(args.idempotency_key);
        }
        sendResponse(id, {
          content: [{ type: 'text', text: JSON.stringify({ payment }) }],
        });
        return;
      }

      if (toolName === 'update_appointment') {
        const dateVal = args.date;
        const isoDatePattern = /^\d{4}-\d{2}-\d{2}$/;
        if (dateVal && !isoDatePattern.test(dateVal)) {
          sendResponse(id, {
            isError: true,
            content: [
              {
                type: 'text',
                text: `Invalid format for parameter 'date'. Expected ISO-8601 format YYYY-MM-DD (e.g. '2026-10-15'). Received invalid value: '${dateVal}'.`,
              },
            ],
          });
          return;
        }

        if (args.dry_run) {
          sendResponse(id, {
            content: [{ type: 'text', text: JSON.stringify({ dry_run: true, status: 'simulated' }) }],
          });
          return;
        }

        appointments.set(args.appointment_id, {
          appointment_id: args.appointment_id,
          date: dateVal,
          updated_at: new Date().toISOString(),
        });

        sendResponse(id, {
          content: [{ type: 'text', text: JSON.stringify({ status: 'updated', appointment_id: args.appointment_id, date: dateVal }) }],
        });
        return;
      }

      if (toolName === 'get_appointment') {
        const appt = appointments.get(args.appointment_id) || { appointment_id: args.appointment_id, date: '2026-10-15' };
        sendResponse(id, {
          content: [{ type: 'text', text: JSON.stringify({ appointment: appt }) }],
        });
        return;
      }

      if (toolName === 'list_invoices') {
        const limit = Math.min(Number(args.limit) || 20, 100);
        const sampleInvoices = Array.from({ length: limit }).map((_, i) => ({
          invoice_id: `inv_100${i}`,
          amount: (i + 1) * 25.5,
          status: 'paid',
        }));

        sendResponse(id, {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                invoices: sampleInvoices,
                has_more: false,
                limit,
              }),
            },
          ],
        });
        return;
      }

      sendError(id, -32601, `Method '${toolName}' not found`);
      return;
    }

    sendError(id, -32601, `Unknown method '${method}'`);
  } catch (err) {
    sendError(null, -32700, `Parse error: ${err.message}`);
  }
});

function sendResponse(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}

function sendError(id, code, message) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\n');
}
