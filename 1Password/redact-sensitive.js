#!/usr/bin/env node

/**
 * JSON Sensitive Data Redaction Script
 *
 * This script recursively traverses JSON objects and removes sensitive information
 * such as passwords, PINs, email addresses, and UUIDs from 1Password export data.
 *
 * Usage:
 *   node redact-sensitive.js input.json output.json
 *   node redact-sensitive.js --help
 *
 * Options:
 *   --config <file>    Specify a configuration file for custom redaction rules
 *   --preserve-keys    Preserve sensitive property keys but redact values only
 *   --dry-run          Show what would be redacted without making changes
 *   --help             Show this help message
 */

const fs = require("node:fs");
const path = require("node:path");

/**
 * Default configuration for sensitive data patterns
 */
const DEFAULT_CONFIG = {
	// Property name patterns to match (case-insensitive)
	sensitiveKeys: [
		"password",
		"pin",
		"email",
		"uuid",
		"secret",
		"token",
		"key",
		"credential",
		"auth",
		"login",
		"passcode",
		"security",
	],

	// Specific property names that are always sensitive
	sensitiveProperties: [
		"password",
		"pin",
		"emailAddress",
		"uuid",
		"secretKey",
		"accessToken",
		"refreshToken",
		"apiKey",
		"privateKey",
		"creditCardNumber",
		"cvv",
		"ssn",
		"socialSecurityNumber",
	],

	// Value patterns that indicate sensitive data
	sensitivePatterns: [
		/^\d{4,6}$/, // PIN-like numbers (4-6 digits)
		/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i, // UUID format
		/^testpass123!$/i, // Example password pattern
		/^fakepassword456$/i, // Example password history pattern
		/^test@example\.com$/i, // Example email pattern
	],

	// Replacement text for sensitive values
	redactionText: "[REDACTED]",

	// Whether to preserve the original property keys
	preserveKeys: false,
};

/**
 * Load configuration from file or use defaults
 */
function loadConfig(configPath) {
	if (!configPath) {
		return DEFAULT_CONFIG;
	}

	try {
		const configData = fs.readFileSync(configPath, "utf8");
		const userConfig = JSON.parse(configData);
		return { ...DEFAULT_CONFIG, ...userConfig };
	} catch (error) {
		console.error(`Error loading config file ${configPath}:`, error.message);
		console.log("Using default configuration.");
		return DEFAULT_CONFIG;
	}
}

/**
 * Check if a property name indicates sensitive data
 */
function isSensitiveKey(key, config) {
	const keyLower = key.toLowerCase();

	// Check exact matches first
	if (config.sensitiveProperties.includes(keyLower)) {
		return true;
	}

	// Check pattern matches
	return config.sensitiveKeys.some((pattern) =>
		keyLower.includes(pattern.toLowerCase()),
	);
}

/**
 * Check if a value matches sensitive patterns
 */
function isSensitiveValue(value, config) {
	if (typeof value !== "string") {
		return false;
	}

	return config.sensitivePatterns.some((pattern) => pattern.test(value));
}

/**
 * Recursively redact sensitive data from an object
 */
function redactObject(obj, config, parentPath = "") {
	if (obj === null || typeof obj !== "object") {
		return obj;
	}

	// Handle arrays
	if (Array.isArray(obj)) {
		return obj.map((item, index) => {
			const currentPath = `${parentPath}[${index}]`;
			return redactObject(item, config, currentPath);
		});
	}

	// Handle objects
	const redacted = {};

	for (const [key, value] of Object.entries(obj)) {
		const currentPath = parentPath ? `${parentPath}.${key}` : key;

		// Check if this key indicates sensitive data
		if (isSensitiveKey(key, config)) {
			if (config.preserveKeys) {
				redacted[key] = config.redactionText;
			}
			// If not preserving keys, skip this property entirely
			continue;
		}

		// Recursively process nested objects/arrays
		if (value !== null && typeof value === "object") {
			redacted[key] = redactObject(value, config, currentPath);
		} else {
			// Check if the value itself is sensitive
			if (isSensitiveValue(value, config)) {
				redacted[key] = config.redactionText;
			} else {
				redacted[key] = value;
			}
		}
	}

	return redacted;
}

/**
 * Process a JSON file and redact sensitive data
 */
function processFile(inputPath, outputPath, config) {
	try {
		// Read input file
		const inputData = fs.readFileSync(inputPath, "utf8");
		const jsonData = JSON.parse(inputData);

		// Redact sensitive data
		const redactedData = redactObject(jsonData, config);

		// Write output file
		fs.writeFileSync(outputPath, JSON.stringify(redactedData, null, 2));

		console.log(`Successfully processed ${inputPath}`);
		console.log(`Redacted data written to ${outputPath}`);

		return true;
	} catch (error) {
		console.error(`Error processing file:`, error.message);
		return false;
	}
}

/**
 * Show help information
 */
function showHelp() {
	console.log(`
JSON Sensitive Data Redaction Script

Usage:
  node redact-sensitive.js [options] <input-file> [output-file]

Arguments:
  input-file     Path to the input JSON file
  output-file    Path for the output JSON file (optional, defaults to input-file.redacted.json)

Options:
  --config <file>       Specify a configuration file for custom redaction rules
  --preserve-keys       Preserve sensitive property keys but redact values only
  --dry-run            Show what would be redacted without making changes
  --help               Show this help message

Examples:
  node redact-sensitive.js data.json redacted-data.json
  node redact-sensitive.js --config custom-config.json --preserve-keys export.json
  node redact-sensitive.js --dry-run sensitive-data.json

Configuration File Format:
  {
    "sensitiveKeys": ["password", "pin", "email", "uuid"],
    "sensitiveProperties": ["password", "pin", "emailAddress"],
    "sensitivePatterns": [
      "\\\\d{4,6}$",
      "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
    ],
    "redactionText": "[REDACTED]",
    "preserveKeys": false
  }

Default Sensitive Properties:
  - password, pin, emailAddress, uuid, secretKey, accessToken, refreshToken
  - apiKey, privateKey, creditCardNumber, cvv, ssn, socialSecurityNumber

Default Sensitive Patterns:
  - PIN-like numbers (4-6 digits)
  - UUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
  - Common password patterns
  - Email address patterns
`);
}

/**
 * Main execution function
 */
function main() {
	const args = process.argv.slice(2);

	// Parse command line arguments
	let inputFile = null;
	let outputFile = null;
	let configFile = null;
	let preserveKeys = false;
	let dryRun = false;

	for (let i = 0; i < args.length; i++) {
		const arg = args[i];

		switch (arg) {
			case "--help":
				showHelp();
				return;

			case "--config":
				configFile = args[++i];
				break;

			case "--preserve-keys":
				preserveKeys = true;
				break;

			case "--dry-run":
				dryRun = true;
				break;

			default:
				if (arg.startsWith("--")) {
					console.error(`Unknown option: ${arg}`);
					showHelp();
					return;
				}

				if (!inputFile) {
					inputFile = arg;
				} else if (!outputFile) {
					outputFile = arg;
				} else {
					console.error("Too many arguments");
					showHelp();
					return;
				}
				break;
		}
	}

	// Validate arguments
	if (!inputFile) {
		console.error("Input file is required");
		showHelp();
		return;
	}

	if (!outputFile) {
		const parsed = path.parse(inputFile);
		outputFile = `${parsed.name}.redacted${parsed.ext}`;
	}

	// Load configuration
	const config = loadConfig(configFile);
	if (preserveKeys) {
		config.preserveKeys = true;
	}

	// Check if input file exists
	if (!fs.existsSync(inputFile)) {
		console.error(`Input file does not exist: ${inputFile}`);
		return;
	}

	// Dry run mode
	if (dryRun) {
		console.log("DRY RUN MODE - No files will be modified");
		console.log(`Input file: ${inputFile}`);
		console.log(`Output file would be: ${outputFile}`);
		console.log(`Configuration: ${configFile || "default"}`);
		console.log(`Preserve keys: ${config.preserveKeys}`);
		console.log("");

		try {
			const inputData = fs.readFileSync(inputFile, "utf8");
			const jsonData = JSON.parse(inputData);

			console.log("Sample of what would be redacted:");
			const sampleRedacted = redactObject(
				JSON.parse(JSON.stringify(jsonData)),
				config,
			);

			// Show first few properties that would be affected
			let count = 0;
			function showRedacted(obj, path = "") {
				if (count >= 10) return; // Limit output

				for (const [key, value] of Object.entries(obj)) {
					const currentPath = path ? `${path}.${key}` : key;

					if (typeof value === "object" && value !== null) {
						showRedacted(value, currentPath);
					} else if (value === "[REDACTED]") {
						console.log(`  ${currentPath}: ${value}`);
						count++;
						if (count >= 10) return;
					}
				}
			}

			showRedacted(sampleRedacted);
		} catch (error) {
			console.error("Error during dry run:", error.message);
		}

		return;
	}

	// Process the file
	const success = processFile(inputFile, outputFile, config);

	if (success) {
		console.log("\nRedaction completed successfully!");
		console.log(`Original: ${inputFile}`);
		console.log(`Redacted: ${outputFile}`);
	} else {
		process.exit(1);
	}
}

// Export functions for use as a module
module.exports = {
	redactObject,
	loadConfig,
	isSensitiveKey,
	isSensitiveValue,
	DEFAULT_CONFIG,
};

// Run the script if called directly
if (require.main === module) {
	main();
}
