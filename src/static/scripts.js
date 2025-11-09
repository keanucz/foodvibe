document.addEventListener("DOMContentLoaded", () => {
  console.info("foodvibe: frontend scripts initialised");
  // --- MODE TOGGLE LOGIC (with localStorage persistence) ---
  const modeToggle = document.getElementById("mode-toggle");
  const demonCSS = document.getElementById("demon-override");
  const h1 = document.querySelector("h1");

  // Helper: apply mode (true = demon, false = angel)
  function applyMode(isDemon) {
    if (!demonCSS) return;

    demonCSS.disabled = !isDemon;
    modeToggle.checked = isDemon;

    // Change header text if present
    if (h1) {
      if (isDemon && h1.textContent.includes("Cuisine Compass")) {
        h1.textContent = h1.textContent.replace(
          "Cuisine Compass",
          "The Demon's Feast",
        );
      } else if (!isDemon && h1.textContent.includes("The Demon's Feast")) {
        h1.textContent = h1.textContent.replace(
          "The Demon's Feast",
          "Cuisine Compass",
        );
      }
    }
  }

  if (modeToggle && demonCSS) {
    // 1️⃣ Load saved mode on page load
    const savedMode = localStorage.getItem("themeMode"); // "demon" or "angel"
    if (savedMode === "demon") {
      applyMode(true);
    } else {
      applyMode(false);
    }

    // 2️⃣ Listen for toggle changes and save them
    modeToggle.addEventListener("change", function () {
      const isDemon = this.checked;
      applyMode(isDemon);

      // Save user preference
      localStorage.setItem("themeMode", isDemon ? "demon" : "angel");
    });
  }
  // --- END MODE TOGGLE LOGIC ---

  // --- RISK SLIDER LOGIC (Page-specific, kept here for completeness) ---
  const riskSlider = document.getElementById("risk-slider");
  const riskValue = document.getElementById("risk-value");

  if (riskSlider && riskValue) {
    const riskTexts = {
      1: "Tried and tested",
      20: "Toes in the water",
      40: "Spicy recommendations",
      60: "Go big or go home",
      80: "Serial gambler",
      100: "99% of gamblers quit before they win big",
    };

    const updateRiskText = () => {
      const val = parseInt(riskSlider.value, 10);

      // Find the closest defined risk level
      let closest = Object.keys(riskTexts).reduce((prev, curr) => {
        return Math.abs(curr - val) < Math.abs(prev - val) ? curr : prev;
      });

      riskValue.textContent = `${riskTexts[closest]}`;

      // Make text red at 100
      if (val >= 91) {
        riskValue.style.color = "red";
      } else {
        riskValue.style.color = ""; // Reset to default
      }
    };

    riskSlider.addEventListener("input", updateRiskText);

    // Initialize risk text
    updateRiskText();
  }

  /**
   * Resets all cards by hiding the rating form and showing the 'Visited' button.
   */
  function closeAllRatings() {
    document.querySelectorAll(".card").forEach((card) => {
      const ratingContainer = card.querySelector(".rating-container");
      const visitedButton = card.querySelector(".visited-button");
      const feedbackElement = card.querySelector(".rating-feedback");
      const ratingForm = card.querySelector(".rating-form");

      // 1. Hide the rating container
      if (ratingContainer && !ratingContainer.classList.contains("hidden")) {
        ratingContainer.classList.add("hidden");
      }

      // 2. Show the visited button (unless already rated)
      if (
        visitedButton &&
        visitedButton.classList.contains("hidden") &&
        !visitedButton.textContent.includes("Rated")
      ) {
        visitedButton.classList.remove("hidden");
      }

      // 3. Clear any temporary feedback
      if (feedbackElement) {
        feedbackElement.classList.add("hidden");
      }

      // 4. Re-enable form pointer events
      if (ratingForm) {
        ratingForm.style.pointerEvents = "auto";
      }
    });
  }

  function bindRatingListeners(root = document) {
    const visitedButtons =
      typeof root.querySelectorAll === "function"
        ? root.querySelectorAll(".visited-button")
        : [];
    visitedButtons.forEach((button) => {
      if (button.dataset.bound === "true") {
        return;
      }
      button.dataset.bound = "true";
      button.addEventListener("click", function () {
        closeAllRatings();

        const card = this.closest(".card");
        const ratingContainer = card?.querySelector(".rating-container");

        if (!ratingContainer) {
          return;
        }

        this.classList.add("hidden");
        ratingContainer.classList.remove("hidden");
      });
    });
    const ratingForms =
      typeof root.querySelectorAll === "function"
        ? root.querySelectorAll(".rating-form")
        : [];
    ratingForms.forEach((form) => {
      if (form.dataset.bound === "true") {
        return;
      }
      form.dataset.bound = "true";
      form.addEventListener("submit", async function (event) {
        event.preventDefault();

        const card = this.closest(".card");
        const feedbackElement = card?.querySelector(".rating-feedback");
        const visitedButton = card?.querySelector(".visited-button");
        const formData = new FormData(this);

        const ratingValue = formData.get("rating");

        if (!ratingValue) {
          alert("Please select a star rating!");
          return;
        }

        console.info("foodvibe: rating submitted", {
          restaurantId: formData.get("restaurant_id"),
          rating: ratingValue,
        });

        if (feedbackElement) {
          feedbackElement.textContent = `Sending ${ratingValue}-star rating...`;
          feedbackElement.classList.remove("hidden");
        }
        this.style.pointerEvents = "none";

        const RATING_ENDPOINT = this.action;

        try {
          const response = await fetch(RATING_ENDPOINT, {
            method: "POST",
            body: new URLSearchParams(formData),
          });

          if (response.ok) {
            if (feedbackElement) {
              feedbackElement.textContent = `Success! Rating submitted.`;
            }
            if (visitedButton) {
              visitedButton.textContent = `Rated (${ratingValue} stars)`;
            }
            console.info("foodvibe: rating submission succeeded", {
              restaurantId: formData.get("restaurant_id"),
              rating: ratingValue,
            });
          } else {
            if (feedbackElement) {
              feedbackElement.textContent = `Error: Could not save rating. Try again.`;
            }
            console.error("Server responded with an error:", response.status);
            this.style.pointerEvents = "auto";
          }
        } catch (error) {
          if (feedbackElement) {
            feedbackElement.textContent = `Network Error: Could not connect.`;
          }
          console.error("Fetch failed:", error);
          this.style.pointerEvents = "auto";
        }
      });
    });
  }

  bindRatingListeners();

  const searchForm = document.getElementById("search-form");
  if (searchForm) {
    const resultsGrid = document.querySelector(".results-grid");
    const searchFeedback = document.getElementById("search-feedback");
    const radiusField = searchForm.querySelector("#radius");
    const searchButton = searchForm.querySelector(".search-button");
    const locationField = searchForm.querySelector("#location");
    const currentLocationButton = document.getElementById(
      "use-current-location",
    );
    const locationDatalist = document.getElementById("location-suggestions");
    const suggestionCache = new Map();
    let autocompleteTimer;
    let suppressLocationInputHandler = false;

    const disableSearch = () => {
      if (searchButton) {
        if (!searchButton.dataset.originalText) {
          searchButton.dataset.originalText =
            searchButton.textContent || "SEARCH";
        }
        searchButton.disabled = true;
        searchButton.textContent = "Searching...";
      }
    };

    const enableSearch = () => {
      if (searchButton) {
        searchButton.disabled = false;
        searchButton.textContent =
          searchButton.dataset.originalText || "SEARCH";
      }
    };

    const setFeedback = (message, isError = false) => {
      if (!searchFeedback) {
        return;
      }
      searchFeedback.textContent = message;
      if (isError) {
        searchFeedback.classList.add("error");
      } else {
        searchFeedback.classList.remove("error");
      }
      searchFeedback.classList.remove("hidden");
    };

    const clearFeedback = () => {
      if (!searchFeedback) {
        return;
      }
      searchFeedback.textContent = "";
      searchFeedback.classList.add("hidden");
      searchFeedback.classList.remove("error");
    };

    const setPresetCoordinates = ({ lat, lng }, source = "manual") => {
      searchForm.dataset.lat = lat.toString();
      searchForm.dataset.lng = lng.toString();
      console.info("foodvibe: preset coordinates stored", { source, lat, lng });
    };

    const clearPresetCoordinates = () => {
      delete searchForm.dataset.lat;
      delete searchForm.dataset.lng;
    };

    const updateLocationSuggestions = (suggestions) => {
      suggestionCache.clear();
      if (locationDatalist) {
        locationDatalist.innerHTML = "";
      }

      suggestions.forEach((item) => {
        suggestionCache.set(item.label, { lat: item.lat, lng: item.lng });
        if (locationDatalist) {
          const option = document.createElement("option");
          option.value = item.label;
          locationDatalist.appendChild(option);
        }
      });
    };

    const requestLocationSuggestions = async (query) => {
      try {
        const url = new URL("https://nominatim.openstreetmap.org/search");
        url.searchParams.set("format", "jsonv2");
        url.searchParams.set("addressdetails", "0");
        url.searchParams.set("limit", "5");
        url.searchParams.set("q", query);

        const response = await fetch(url.toString(), {
          headers: {
            Accept: "application/json",
            "User-Agent": "foodvibe-app/1.0",
          },
        });

        if (!response.ok) {
          console.warn(
            "foodvibe: autocomplete response not ok",
            response.status,
          );
          return [];
        }

        const data = await response.json();
        return data
          .map((entry) => ({
            label: entry.display_name,
            lat: parseFloat(entry.lat),
            lng: parseFloat(entry.lon),
          }))
          .filter(
            (entry) => Number.isFinite(entry.lat) && Number.isFinite(entry.lng),
          );
      } catch (error) {
        console.warn("foodvibe: autocomplete fetch failed", error);
        return [];
      }
    };

    if (locationField) {
      const applyCachedSelection = () => {
        const selection = suggestionCache.get(locationField.value.trim());
        if (selection) {
          setPresetCoordinates(selection, "autocomplete");
        }
      };

      locationField.addEventListener("input", (event) => {
        if (suppressLocationInputHandler) {
          suppressLocationInputHandler = false;
          return;
        }

        clearPresetCoordinates();

        const value = event.target.value.trim();
        if (!value || value.length < 3) {
          if (autocompleteTimer) {
            clearTimeout(autocompleteTimer);
          }
          updateLocationSuggestions([]);
          return;
        }

        if (autocompleteTimer) {
          clearTimeout(autocompleteTimer);
        }

        autocompleteTimer = setTimeout(async () => {
          const query = value;
          const suggestions = await requestLocationSuggestions(query);
          if (locationField && locationField.value.trim() !== query) {
            return;
          }
          updateLocationSuggestions(suggestions);
        }, 300);
      });

      locationField.addEventListener("change", applyCachedSelection);
      locationField.addEventListener("blur", applyCachedSelection);
    }

    if (currentLocationButton && locationField) {
      currentLocationButton.addEventListener("click", () => {
        if (!navigator.geolocation) {
          setFeedback("Geolocation is not supported by your browser.", true);
          return;
        }

        const handleSuccess = (position) => {
          const { latitude, longitude } = position.coords;
          const coords = {
            lat: latitude,
            lng: longitude,
          };

          suppressLocationInputHandler = true;
          locationField.value = `${latitude.toFixed(6)},${longitude.toFixed(6)}`;
          locationField.focus();

          setPresetCoordinates(coords, "browser");
          setFeedback("Using your current location.");
          currentLocationButton.disabled = false;
        };

        const handleError = (error) => {
          console.warn("foodvibe: current location access failed", error);
          setFeedback(
            error.message || "Unable to access your current location.",
            true,
          );
          currentLocationButton.disabled = false;
        };

        currentLocationButton.disabled = true;
        setFeedback("Fetching your current location...");
        clearPresetCoordinates();
        updateLocationSuggestions([]);

        navigator.geolocation.getCurrentPosition(handleSuccess, handleError, {
          enableHighAccuracy: true,
          timeout: 7000,
          maximumAge: 0,
        });
      });
    }

    searchForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      if (!resultsGrid) {
        return;
      }

      const locationValue = locationField?.value.trim() || "";
      if (!locationValue) {
        alert("Please enter a location.");
        return;
      }

      const cuisine = searchForm.cuisine?.value || "";
      const risk = searchForm.risk?.value || "1";
      const radiusFromInput = radiusField?.value
        ? parseInt(radiusField.value, 10)
        : NaN;

      console.info("foodvibe: search submitted", {
        cuisine,
        location: locationValue,
        risk,
        radiusFromInput,
      });

      disableSearch();
      clearFeedback();

      try {
        let coords = null;

        if (searchForm.dataset.lat && searchForm.dataset.lng) {
          const presetLat = parseFloat(searchForm.dataset.lat);
          const presetLng = parseFloat(searchForm.dataset.lng);
          if (Number.isFinite(presetLat) && Number.isFinite(presetLng)) {
            coords = { lat: presetLat, lng: presetLng };
            console.info("foodvibe: using preset coordinates", coords);
          } else {
            delete searchForm.dataset.lat;
            delete searchForm.dataset.lng;
          }
        }

        if (!coords) {
          const cachedSuggestion = suggestionCache.get(locationValue);
          if (cachedSuggestion) {
            coords = cachedSuggestion;
            console.info("foodvibe: using autocomplete coordinates", coords);
          }
        }

        if (!coords) {
          coords = await resolveCoordinates(locationValue);
        }

        console.info("foodvibe: coordinates resolved", coords);
        const radius = Number.isFinite(radiusFromInput)
          ? radiusFromInput
          : riskToRadius(Number(risk));

        console.info("foodvibe: requesting backend search", {
          radius,
          coords,
          cuisine,
          risk,
        });

        const params = new URLSearchParams({
          cuisine,
          risk,
          lat: coords.lat.toString(),
          lng: coords.lng.toString(),
        });
        if (Number.isFinite(radius) && radius > 0) {
          params.set("radius", radius.toString());
        }

        const response = await fetch(`/search?${params.toString()}`);
        if (!response.ok) {
          throw new Error(`Search failed with status ${response.status}`);
        }

        const payload = await response.json();
        const results = Array.isArray(payload.results) ? payload.results : [];

        console.info("foodvibe: search results received", {
          count: results.length,
          radius,
        });

        renderResults(resultsGrid, results);
        bindRatingListeners(resultsGrid);

        setFeedback(
          results.length
            ? `Found ${results.length} independent spots near ${locationValue}.`
            : `No independent spots found near ${locationValue}.`,
        );
      } catch (error) {
        console.error(error);
        setFeedback(
          error instanceof Error
            ? error.message
            : "We hit a snag while searching. Please try again.",
          true,
        );
      } finally {
        enableSearch();
      }
    });
  }
});

function renderResults(resultsGrid, results) {
  if (!resultsGrid) {
    return;
  }

  if (!Array.isArray(results) || results.length === 0) {
    console.warn("foodvibe: no results to render");
    resultsGrid.innerHTML =
      '<p class="empty-state">No venues matched your search. Try adjusting the radius or cuisine.</p>';
    return;
  }

  console.info("foodvibe: rendering results", { count: results.length });
  const fragment = document.createDocumentFragment();

  results.forEach((result) => {
    const card = document.createElement("div");
    card.className = "card";

    const cuisine = result?.classification?.cuisine || "Unknown";
    const confidence = formatConfidence(result?.classification?.confidence);
    const healthy = result?.classification?.healthy === true;
    const rationale = result?.classification?.rationale || "";
    const address = result?.formattedAddress || "";

    const rating = formatRating(result?.rating, result?.userRatingsTotal);
    const mapLink = result?.googleMapsUri || result?.googleMapsURI || "";

    card.innerHTML = `
      <h3>${escapeHtml(result?.name || "Unnamed spot")}</h3>
      ${address ? `<p>Address: ${escapeHtml(address)}</p>` : ""}
      <p>Cuisine: ${escapeHtml(cuisine)}</p>
      <p>Healthy focus: ${healthy ? "Yes" : "No"}</p>
      <p>Confidence: ${confidence}</p>
      ${rating ? `<p>${rating}</p>` : ""}
      ${rationale ? `<p class="rationale">${escapeHtml(rationale)}</p>` : ""}
      ${mapLink ? `<p><a href="${encodeURI(mapLink)}" target="_blank" rel="noopener">Open in Google Maps</a></p>` : ""}
    `;

    fragment.appendChild(card);
  });

  resultsGrid.replaceChildren(fragment);
}

function escapeHtml(value) {
  return (value ?? "").replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      case "'":
        return "&#39;";
      default:
        return char;
    }
  });
}

function formatConfidence(value) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "n/a";
  }
  const percentage = Math.round(Math.min(Math.max(value, 0), 1) * 100);
  return `${percentage}%`;
}

function formatRating(rating, total) {
  if (typeof rating !== "number" || Number.isNaN(rating)) {
    return "";
  }
  const reviews = typeof total === "number" && total > 0 ? total : null;
  return `Rating: ${rating.toFixed(1)}${reviews ? ` (${reviews} reviews)` : ""}`;
}

function riskToRadius(riskValue) {
  const normalized = Number.isFinite(riskValue) ? riskValue : 1;
  const clamped = Math.min(Math.max(normalized, 1), 100);
  const minRadius = 1000; // meters
  const maxRadius = 6000; // meters
  const proportion = (clamped - 1) / 99;
  return Math.round(minRadius + proportion * (maxRadius - minRadius));
}

async function resolveCoordinates(query) {
  const geocoded = await geocodeLocation(query);
  if (geocoded) {
    return geocoded;
  }

  if ("geolocation" in navigator) {
    try {
      const position = await getCurrentPosition({
        timeout: 5000,
        enableHighAccuracy: true,
      });
      console.info("foodvibe: using browser geolocation fallback");
      return {
        lat: position.coords.latitude,
        lng: position.coords.longitude,
      };
    } catch (error) {
      console.warn("Geolocation fallback failed", error);
    }
  }

  throw new Error("Unable to determine coordinates for that location.");
}

async function geocodeLocation(query) {
  if (!query) {
    return null;
  }

  console.info("foodvibe: geocoding query", query);

  const url = new URL("https://nominatim.openstreetmap.org/search");
  url.searchParams.set("format", "jsonv2");
  url.searchParams.set("limit", "1");
  url.searchParams.set("addressdetails", "0");
  url.searchParams.set("q", query);

  try {
    const response = await fetch(url.toString(), {
      headers: {
        Accept: "application/json",
        "User-Agent": "foodvibe-app/1.0",
      },
    });
    if (!response.ok) {
      console.warn("foodvibe: geocoding response not ok", response.status);
      throw new Error(`Geocoding failed with status ${response.status}`);
    }
    const data = await response.json();
    if (Array.isArray(data) && data.length > 0) {
      const { lat, lon } = data[0];
      const latitude = parseFloat(lat);
      const longitude = parseFloat(lon);
      if (Number.isFinite(latitude) && Number.isFinite(longitude)) {
        console.info("foodvibe: geocoding success", { latitude, longitude });
        return { lat: latitude, lng: longitude };
      }
    }
    console.warn("foodvibe: geocoding returned no candidates");
    return null;
  } catch (error) {
    console.warn("Geocoding request failed", error);
    return null;
  }
}

function getCurrentPosition(options = {}) {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error("Geolocation is not supported by this browser."));
      return;
    }

    navigator.geolocation.getCurrentPosition(resolve, reject, options);
  });
}
