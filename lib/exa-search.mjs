// Server-only Exa search for the "Live Threat Intelligence" section.
// EXA_API_KEY is read from the environment here and never leaves the server.
import Exa from "exa-js";

const MAX_RESULTS = 5;
const MAX_QUERY_LENGTH = 200;
const MAX_HIGHLIGHTS = 3;

/** Error carrying the HTTP status the route should answer with. */
export class ThreatSearchError extends Error {
  constructor(message, status = 500) {
    super(message);
    this.name = "ThreatSearchError";
    this.status = status;
  }
}

let client;

function getClient() {
  const apiKey = process.env.EXA_API_KEY;
  if (!apiKey) {
    throw new ThreatSearchError(
      "Threat search is not configured yet: EXA_API_KEY is missing on the server. Add it to your local .env file and restart the server.",
      503,
    );
  }
  client ??= new Exa(apiKey);
  return client;
}

function normalizeQuery(raw) {
  const query = typeof raw === "string" ? raw.trim().replace(/\s+/g, " ") : "";
  if (!query) {
    throw new ThreatSearchError("Type a topic, vulnerability or campaign to search for.", 400);
  }
  if (query.length > MAX_QUERY_LENGTH) {
    throw new ThreatSearchError(`Keep your search under ${MAX_QUERY_LENGTH} characters.`, 400);
  }
  return query;
}

function toResult(result) {
  const highlights = Array.isArray(result?.highlights)
    ? result.highlights.filter((h) => typeof h === "string" && h.trim()).map((h) => h.trim())
    : [];

  return {
    title: typeof result?.title === "string" && result.title.trim() ? result.title.trim() : null,
    url: result?.url ?? null,
    publishedDate: result?.publishedDate ?? null,
    author: result?.author ?? null,
    highlights: highlights.slice(0, MAX_HIGHLIGHTS),
  };
}

function searchError(error) {
  if (error instanceof ThreatSearchError) return error;

  const status = error?.statusCode;
  if (status === 401) {
    return new ThreatSearchError(
      "Exa rejected the API key (401). Check EXA_API_KEY in your local .env file and restart the server.",
      502,
    );
  }
  if (status === 402) {
    return new ThreatSearchError(
      "Exa credits are exhausted (402). Top up the Exa account to run more searches.",
      402,
    );
  }
  if (status === 429) {
    return new ThreatSearchError("Exa rate limit reached (429). Wait a moment and try again.", 429);
  }
  const detail = status ? ` (${status})` : "";
  return new ThreatSearchError(`Exa could not complete that search${detail}. Please try again.`, 502);
}

/**
 * Runs one Exa search for the threat-intel section.
 * @param {string} rawQuery
 * @returns {Promise<{query: string, results: Array<object>, searchedAt: string}>}
 */
export async function searchThreatIntel(rawQuery) {
  const query = normalizeQuery(rawQuery);

  let response;
  try {
    response = await getClient().search(query, {
      type: "auto",
      numResults: MAX_RESULTS,
      contents: { highlights: true },
    });
  } catch (error) {
    throw searchError(error);
  }

  const results = (response?.results ?? []).map(toResult).filter((result) => result.url);
  return { query, results, searchedAt: new Date().toISOString() };
}
