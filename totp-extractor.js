/**
 * TOTP Extractor for 1Password Export Data
 *
 * Extracts TOTP values from 1Password JSON export data.
 * Handles nested account/vault/item structures and extracts
 * TOTP URIs from Security sections.
 */

const fs = require('node:fs');

/**
 * Extracts TOTP values from 1Password export JSON data
 * @param {string} filePath - Path to the 1Password export JSON file
 * @returns {Object[]} Array of TOTP entries with issuer, account, and secret
 */
function extractTOTPs(filePath) {
    try {
        // Read and parse the JSON file
        console.log(`Attempting to read file: ${filePath || 'export.data'}`);
        const rawData = fs.readFileSync(filePath || 'export.data', 'utf8');
        console.log(`Successfully read file, size: ${rawData.length} characters`);
        const data = JSON.parse(rawData);
        console.log(`Parsed JSON data. Top level keys: ${Object.keys(data).join(', ')}`);

        const totpEntries = [];

        // Navigate the nested structure: accounts[].vaults[].items[].details.sections[].fields[]
        if (data.accounts && Array.isArray(data.accounts)) {
            console.log(`Found ${data.accounts.length} accounts`);
            for (const account of data.accounts) {
                if (account.vaults && Array.isArray(account.vaults)) {
                    console.log(`Account has ${account.vaults.length} vaults`);
                    for (const vault of account.vaults) {
                        if (vault.items && Array.isArray(vault.items)) {
                            console.log(`Vault "${vault.attrs?.name || 'Unknown'}" has ${vault.items.length} items`);
                            for (const item of vault.items) {
                                if (item.details?.sections && Array.isArray(item.details.sections)) {
                                    console.log(`Item "${item.overview?.title || 'Unknown'}" has ${item.details.sections.length} sections`);
                                    for (const section of item.details.sections) {
                                        // Look for Security sections or any section containing TOTP fields
                                        if (section.fields && Array.isArray(section.fields)) {
                                            console.log(`Section "${section.title || section.name || 'Unknown'}" has ${section.fields.length} fields`);
                                            for (const field of section.fields) {
                                                console.log(`Checking field: "${field.title || 'No title'}", has TOTP: ${!!(field.value?.totp || field.value)}`);
                                                // Check if this field contains TOTP data - handle both otpauth:// URLs and raw secrets
                                                if (field.title === 'one-time password') {
                                                    const totpValue = field.value?.totp || field.value;
                                                    if (totpValue) {
                                                        console.log(`Found TOTP: ${totpValue}`);

                                                        // Extract issuer from item title
                                                        const issuer = item.overview?.title || 'Unknown';

                                                        // Find account/email by converting entire item to string and using regex
                                                        let account = 'user'; // Default account as requested
                                                        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;

                                                        // Convert entire item object to JSON string and search for emails
                                                        const itemString = JSON.stringify(item);
                                                        const emailMatch = itemString.match(emailRegex);

                                                        if (emailMatch) {
                                                            account = emailMatch[0];
                                                            console.log(`Found email in item "${item.overview?.title || 'Unknown'}": ${account}`);
                                                        } else {
                                                            console.log(`No email found in item "${item.overview?.title || 'Unknown'}", using default: ${account}`);
                                                        }

                                                        // Use TOTP URI as secret if it's already in otpauth:// format
                                                        let secret = totpValue;
                                                        if (totpValue.startsWith('otpauth://')) {
                                                            // For otpauth URLs, use the entire URI as the secret (no parsing needed)
                                                            secret = totpValue;
                                                            console.log(`Using full TOTP URI as secret for ${issuer}`);
                                                        } else {
                                                            console.log(`Using raw secret for ${issuer}: ${secret}`);
                                                        }

                                                        // Extract additional info from TOTP URI if available
                                                        let finalIssuer = issuer;
                                                        let finalAccount = account;
                                                        let cleanSecret = secret;
                                                        let notes = '';

                                                        if (secret.startsWith('otpauth://')) {
                                                            try {
                                                                const url = new URL(secret);
                                                                const uriIssuer = url.searchParams.get('issuer');
                                                                const uriAccount = url.pathname.split(':')[1] || url.pathname.substring(6);

                                                                // Use URI data if we don't have better data from item
                                                                if (!finalIssuer || finalIssuer === 'Unknown') {
                                                                    finalIssuer = uriIssuer || uriAccount.split(':')[0] || 'Unknown';
                                                                }
                                                                if (!finalAccount || finalAccount === 'user') {
                                                                    finalAccount = uriAccount || 'Unknown';
                                                                }

                                                                // Extract clean secret from URI
                                                                cleanSecret = url.searchParams.get('secret') || secret;

                                                                // Add algorithm, digits, period to notes if different from defaults
                                                                const algorithm = url.searchParams.get('algorithm') || 'SHA1';
                                                                const digits = url.searchParams.get('digits') || '6';
                                                                const period = url.searchParams.get('period') || '30';

                                                                const notesParts = [];
                                                                if (algorithm !== 'SHA1') notesParts.push(`Algorithm: ${algorithm}`);
                                                                if (digits !== '6') notesParts.push(`Digits: ${digits}`);
                                                                if (period !== '30') notesParts.push(`Period: ${period}`);

                                                                notes = notesParts.join(', ');
                                                            } catch (error) {
                                                                console.log(`Error parsing TOTP URI: ${error.message}`);
                                                                cleanSecret = secret;
                                                            }
                                                        }

                                                        totpEntries.push({
                                                            issuer: finalIssuer,
                                                            account: finalAccount,
                                                            secret: cleanSecret,
                                                            notes: notes || undefined
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    console.log(`Item "${item.overview?.title || 'Unknown'}" has no sections`);
                                }
                            }
                        } else {
                            console.log(`Vault "${vault.attrs?.name || 'Unknown'}" has no items`);
                        }
                    }
                } else {
                    console.log('Account has no vaults');
                }
            }
        }

        return totpEntries;

    } catch (error) {
        console.error(`Error processing file ${filePath}:`, error.message);
        throw error;
    }
}

/**
 * Main execution function
 */
/**
 * Outputs TOTP entries to output.txt file with constructed TOTP URIs
 * @param {Object[]} totpEntries - Array of TOTP entries with issuer, account, and secret
 */
function outputToTXT(totpEntries) {
    if (totpEntries.length === 0) {
        console.log('No TOTP entries found in the export data.');
        return;
    }

    console.log(`Found ${totpEntries.length} TOTP entries. Writing to output.txt...`);

    // Construct TOTP URIs and write to output.txt
    const totpURIs = totpEntries.map(entry => {
        // URL encode the account for proper URI format
        const encodedAccount = encodeURIComponent(entry.account);
        const encodedIssuer = encodeURIComponent(entry.issuer);

        // Construct the TOTP URI
        return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${entry.secret}&issuer=${encodedIssuer}`;
    });

    // Write to output.txt with each URI on a new line
    fs.writeFileSync('output.txt', totpURIs.join('\n'), 'utf8');
    console.log('Successfully wrote TOTP URIs to output.txt');

    // Also log to console for verification
    console.log('\nConstructed TOTP URIs:');
    totpURIs.forEach((uri, index) => {
        console.log(`${index + 1}. ${uri}`);
    });
}

function main() {
    try {
        // Get file path from command line arguments or use default
        const filePath = process.argv[2] || 'export.data';
        console.log(`Starting TOTP extraction from: ${filePath}`);
        const totpEntries = extractTOTPs(filePath);
        outputToTXT(totpEntries);

    } catch (error) {
        console.error('Extraction failed:', error.message);
        process.exit(1);
    }
}

// Handle command line arguments for direct execution
if (require.main === module) {
    main();
}

module.exports = {
    extractTOTPs,
    outputToTXT
};
