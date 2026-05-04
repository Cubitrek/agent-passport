/**
 * Inlined copy of schemas/agent-passport.schema.json so the published npm
 * package has zero runtime fs dependencies. Regenerate after editing the
 * canonical schema with `node scripts/sync-schema.mjs`.
 */

export const schema = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://cubitrek.com/spec/agent-passport/v0.1/schema.json",
  "title": "Agent Passport v0.1",
  "description": "A standard for verifiable, business-issued identity and authority for AI agents that talk to other AI agents across organisational boundaries. Authored by Cubitrek, 2026.",
  "type": "object",
  "required": [
    "version",
    "issuer",
    "agent",
    "authority",
    "issuedAt",
    "expiresAt",
    "signature"
  ],
  "additionalProperties": true,
  "properties": {
    "version": {
      "type": "string",
      "const": "0.1.0",
      "description": "Spec version. Must be 0.1.0 for this version."
    },
    "issuer": {
      "type": "object",
      "required": ["domain", "legalName", "displayName", "signingKeyDns"],
      "additionalProperties": true,
      "properties": {
        "domain": {
          "type": "string",
          "format": "hostname",
          "description": "Apex domain of the issuer. Must match the host serving the passport."
        },
        "legalName": { "type": "string", "minLength": 1 },
        "displayName": { "type": "string", "minLength": 1 },
        "logo": { "type": "string", "format": "uri" },
        "signingKeyDns": {
          "type": "string",
          "pattern": "^(_?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\\.(_?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$",
          "description": "DNS name of the TXT record carrying the Ed25519 public key, e.g. _agent-passport.acme.example. Underscore-prefixed labels are permitted (RFC 6763)."
        },
        "contact": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "email": { "type": "string", "format": "email" },
            "url": { "type": "string", "format": "uri" }
          }
        }
      }
    },
    "agent": {
      "type": "object",
      "required": ["id", "displayName", "purpose", "endpoints"],
      "additionalProperties": true,
      "properties": {
        "id": {
          "type": "string",
          "minLength": 3,
          "description": "Stable identifier of the agent. Convention: {issuer.domain}:{role}-v{revision}."
        },
        "displayName": { "type": "string", "minLength": 1 },
        "purpose": { "type": "string", "minLength": 10 },
        "model": { "type": "string" },
        "endpoints": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "a2a": { "type": "string", "format": "uri" },
            "mcp": { "type": "string", "format": "uri" },
            "rest": { "type": "string", "format": "uri" }
          },
          "anyOf": [
            { "required": ["a2a"] },
            { "required": ["mcp"] },
            { "required": ["rest"] }
          ]
        }
      }
    },
    "authority": {
      "type": "object",
      "required": [
        "scope",
        "spendCeiling",
        "humanInLoop",
        "decisionAudit"
      ],
      "additionalProperties": true,
      "properties": {
        "scope": {
          "type": "array",
          "items": {
            "type": "string",
            "pattern": "^[a-z][a-z0-9-]*\\.[a-z][a-z0-9-]*$"
          },
          "minItems": 1,
          "uniqueItems": true,
          "description": "Capability strings using subject.verb notation, e.g. procurement.purchase."
        },
        "spendCeiling": {
          "type": "object",
          "required": ["amount", "currency", "perEngagement"],
          "additionalProperties": false,
          "properties": {
            "amount": { "type": "number", "minimum": 0 },
            "currency": {
              "type": "string",
              "pattern": "^[A-Z]{3}$",
              "description": "ISO 4217 currency code."
            },
            "perEngagement": { "type": "boolean" }
          }
        },
        "humanInLoop": {
          "type": "object",
          "required": ["above", "escalation", "slaHours"],
          "additionalProperties": false,
          "properties": {
            "above": {
              "type": "object",
              "required": ["amount", "currency"],
              "additionalProperties": false,
              "properties": {
                "amount": { "type": "number", "minimum": 0 },
                "currency": {
                  "type": "string",
                  "pattern": "^[A-Z]{3}$"
                }
              }
            },
            "escalation": {
              "type": "string",
              "description": "Email address or URL for human escalation."
            },
            "slaHours": { "type": "number", "minimum": 0 }
          }
        },
        "decisionAudit": {
          "type": "string",
          "description": "URL template that resolves to a signed audit transcript. Must contain the literal substring {engagementId}."
        },
        "termsUrl": { "type": "string", "format": "uri" }
      }
    },
    "counterparties": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "allowlist": {
          "type": "array",
          "items": { "type": "string", "format": "hostname" },
          "uniqueItems": true
        },
        "blocklist": {
          "type": "array",
          "items": { "type": "string", "format": "hostname" },
          "uniqueItems": true
        },
        "openTo": {
          "type": "string",
          "enum": ["any", "verified-passports", "allowlist-only"]
        }
      }
    },
    "compliance": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "dataClassification": {
          "type": "string",
          "enum": ["public", "internal", "confidential-business", "regulated-pii"]
        },
        "regions": {
          "type": "array",
          "items": { "type": "string", "pattern": "^[A-Z]{2}$" },
          "uniqueItems": true
        },
        "subprocessors": {
          "type": "array",
          "items": { "type": "string" },
          "uniqueItems": true
        },
        "humanReviewLog": { "type": "boolean" }
      }
    },
    "issuedAt": {
      "type": "string",
      "format": "date-time"
    },
    "expiresAt": {
      "type": "string",
      "format": "date-time"
    },
    "revocationListUrl": {
      "type": "string",
      "format": "uri"
    },
    "signature": {
      "type": "object",
      "required": ["alg", "keyId", "value"],
      "additionalProperties": false,
      "properties": {
        "alg": { "type": "string", "const": "ed25519" },
        "keyId": { "type": "string", "minLength": 1 },
        "value": {
          "type": "string",
          "description": "Base64url-encoded Ed25519 signature over the canonical JSON form of the passport with signature.value set to the empty string."
        }
      }
    }
  }
} as const;
