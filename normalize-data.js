#!/usr/bin/env node

/**
 * JSON Data Normalization Script
 *
 * This script normalizes JSON input data according to specified rules:
 * - Keeps only items with type "login", "note", or "identity"
 * - Sets extraFields to empty array for all items
 * - Sets totpUri to empty string for all items
 * - Preserves all other data structure and fields unchanged
 *
 * Usage:
 *   echo '{"data": "..."}' | node normalize-data.js
 *   node normalize-data.js input.json
 *   node normalize-data.js input.json > output.json
 *
 * @param {string} [filePath] - Optional file path to read JSON from. If not provided, reads from stdin.
 */

const fs = require('node:fs');

/**
 * Normalizes a single item according to the specified rules
 * @param {Object} item - The item object to normalize
 * @returns {Object|null} - The normalized item or null if item should be filtered out
 */
function normalizeItem(item) {
  // Check if item has the required data structure
  if (!item || !item.data || !item.data.type) {
    return null;
  }

  // Only keep items with specified types
  const allowedTypes = ['login', 'note', 'identity'];
  if (!allowedTypes.includes(item.data.type)) {
    return null;
  }

  // Create normalized item with all other fields preserved
  const normalizedItem = {
    ...item,
    data: {
      ...item.data,
      extraFields: [],  // Normalize extraFields to empty array
      ...(item.data.content && {
        content: {
          ...item.data.content,
          totpUri: ''  // Normalize totpUri to empty string
        }
      })
    }
  };

  return normalizedItem;
}

/**
 * Normalizes all items in a vault
 * @param {Object} vault - The vault object containing items
 * @returns {Object} - The vault with normalized items
 */
function normalizeVault(vault) {
  if (!vault || !vault.items) {
    return vault;
  }

  const normalizedItems = vault.items
    .map(normalizeItem)
    .filter(item => item !== null);  // Remove filtered out items

  return {
    ...vault,
    items: normalizedItems
  };
}

/**
 * Normalizes the entire data structure recursively
 * @param {Object} data - The complete JSON data structure
 * @returns {Object} - The normalized data structure
 */
function normalizeData(data) {
  if (!data || !data.vaults) {
    return data;
  }

  const normalizedVaults = {};

  // Process each vault
  for (const [vaultId, vault] of Object.entries(data.vaults)) {
    normalizedVaults[vaultId] = normalizeVault(vault);
  }

  return {
    ...data,
    vaults: normalizedVaults
  };
}

/**
 * Reads JSON data from stdin
 * @returns {Promise<Object>} - The parsed JSON data
 */
function readFromStdin() {
  return new Promise((resolve, reject) => {
    let data = '';

    process.stdin.on('data', chunk => {
      data += chunk;
    });

    process.stdin.on('end', () => {
      try {
        const jsonData = JSON.parse(data);
        resolve(jsonData);
      } catch (error) {
        reject(new Error(`Invalid JSON from stdin: ${error.message}`));
      }
    });

    process.stdin.on('error', error => {
      reject(new Error(`Error reading from stdin: ${error.message}`));
    });
  });
}

/**
 * Reads JSON data from a file
 * @param {string} filePath - Path to the JSON file
 * @returns {Promise<Object>} - The parsed JSON data
 */
function readFromFile(filePath) {
  return new Promise((resolve, reject) => {
    fs.readFile(filePath, 'utf8', (error, data) => {
      if (error) {
        reject(new Error(`Error reading file ${filePath}: ${error.message}`));
        return;
      }

      try {
        const jsonData = JSON.parse(data);
        resolve(jsonData);
      } catch (error) {
        reject(new Error(`Invalid JSON in file ${filePath}: ${error.message}`));
      }
    });
  });
}

/**
 * Main function to run the normalization process
 */
async function main() {
  try {
    let jsonData;

    // Check if file path is provided as command line argument
    const filePath = process.argv[2];

    if (filePath) {
      jsonData = await readFromFile(filePath);
    } else {
      jsonData = await readFromStdin();
    }

    // Normalize the data
    const normalizedData = normalizeData(jsonData);

    // Write normalized JSON to output.json file
    fs.writeFileSync('output.json', JSON.stringify(normalizedData, null, 2));

    // Confirm file was written successfully
    console.log('Normalized data successfully written to output.json');

  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

// Run the script
main();
