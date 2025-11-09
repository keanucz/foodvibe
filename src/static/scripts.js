document.addEventListener("DOMContentLoaded", () => {
  // --- MODE TOGGLE LOGIC ---
  const modeToggle = document.getElementById("mode-toggle");
  const demonCSS = document.getElementById("demon-override");
  const h1 = document.querySelector("h1");

  if (modeToggle && demonCSS) {
    modeToggle.addEventListener("change", function () {
      const isDemon = this.checked;

      // Enable or disable the demon-mode CSS file
      demonCSS.disabled = !isDemon;

      // Update header text on home/index
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
    });
  }
  // --- END OF MODE TOGGLE LOGIC ---

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

  // --- 1. VISITED BUTTON LOGIC (Show the form, close others first) ---
  document.querySelectorAll(".visited-button").forEach((button) => {
    button.addEventListener("click", function () {
      // Close all other rating forms across the page
      closeAllRatings();

      const card = this.closest(".card");
      const ratingContainer = card.querySelector(".rating-container");

      // Handle the clicked card
      this.classList.add("hidden"); // Hide the visited button
      ratingContainer.classList.remove("hidden"); // Show the rating container
    });
  });

  // --- 2. FORM SUBMISSION LOGIC (POST via Fetch) ---
  document.querySelectorAll(".rating-form").forEach((form) => {
    form.addEventListener("submit", async function (event) {
      event.preventDefault(); // Stop the default page reload

      const card = this.closest(".card");
      const feedbackElement = card.querySelector(".rating-feedback");
      const visitedButton = card.querySelector(".visited-button");
      const formData = new FormData(this);

      const ratingValue = formData.get("rating");

      if (!ratingValue) {
        alert("Please select a star rating!");
        return;
      }

      feedbackElement.textContent = `Sending ${ratingValue}-star rating...`;
      feedbackElement.classList.remove("hidden");
      this.style.pointerEvents = "none"; // Temporarily disable form

      const RATING_ENDPOINT = this.action;

      try {
        const response = await fetch(RATING_ENDPOINT, {
          method: "POST",
          // Note: URLSearchParams works well for standard form data
          body: new URLSearchParams(formData),
        });

        if (response.ok) {
          feedbackElement.textContent = `Success! Rating submitted.`;
          if (visitedButton) {
            visitedButton.textContent = `Rated (${ratingValue} stars)`;
          }
          // Keep form disabled after success
        } else {
          feedbackElement.textContent = `Error: Could not save rating. Try again.`;
          console.error("Server responded with an error:", response.status);
          this.style.pointerEvents = "auto"; // Re-enable form
        }
      } catch (error) {
        feedbackElement.textContent = `Network Error: Could not connect.`;
        console.error("Fetch failed:", error);
        this.style.pointerEvents = "auto"; // Re-enable form
      }
    });
  });
});
