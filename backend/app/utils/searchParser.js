/**
 * Advanced Enterprise Search Syntax Parser for SOCRA AI
 * Converts "host:MANI severity:high credential theft" into a structured query object.
 */
export const parseSearchQuery = (inputString) => {
  const result = {
    tokens: {},
    keywords: []
  };

  if (!inputString || typeof inputString !== 'string') return result;

  // Regex to match key:value patterns, supporting double-quoted strings for values with spaces
  // Example matches -> host:MANI, user:"Domain Admin"
  const tokenRegex = /(\w+):(?:"([^"]*)"|(\S+))/g;
  
  let match;
  let cleanedString = inputString;

  // 1. Extract structural token filters
  while ((match = tokenRegex.exec(inputString)) !== null) {
    const key = match[1].toLowerCase().trim();
    const value = (match[2] || match[3]).trim();
    result.tokens[key] = value;
    
    // Strip the token out of the raw string to isolate remaining generic keywords
    cleanedString = cleanedString.replace(match[0], '');
  }

  // 2. Clean and capture loose keywords for full-text search fallbacks
  result.keywords = cleanedString
    .split(/\s+/)
    .map(word => word.trim())
    .filter(word => word.length > 0);

  return result;
};