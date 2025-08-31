// result.js
document.addEventListener('DOMContentLoaded', function () {
    const container = document.getElementById('recommendationsList');
    const loadingElement = container.querySelector('.loading');
    
    try {
        // Hide loading spinner after processing
        setTimeout(() => {
            processRecommendations();
            loadingElement.style.display = 'none';
        }, 800); // Simulate processing delay
    } catch (error) {
        console.error("Error loading recommendations:", error);
        loadingElement.style.display = 'none';
        showErrorMessage();
    }

    // Retake button
    const retakeBtn = document.querySelector('.retake-btn');
    if (retakeBtn) {
        retakeBtn.addEventListener('click', () => {
            window.location.href = '/questionnaire';
        });
    }
});

function processRecommendations() {
    const container = document.getElementById('recommendationsList');
    const recommendations = JSON.parse(document.getElementById('recommendations-data').textContent);

    if (!recommendations || recommendations.length === 0) {
        container.innerHTML = `
            <div class="no-results">
                <h3>No recommendations found</h3>
                <p>We couldn't find any courses matching your profile. Please try adjusting your answers.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = '';
    recommendations.forEach((rec, index) => {
        const matchPercent = rec.match_percent
            ? rec.match_percent.toFixed(1)
            : rec.match_score
            ? (rec.match_score * 100).toFixed(1)
            : 'N/A';

        const courseId = rec.course_id || rec.id || `course-${index}`;

        const card = document.createElement('div');
        card.className = 'recommendation-card';
        card.innerHTML = `
            <div class="match-percentage">${matchPercent}% Match</div>
            <h3 class="course-name">${index + 1}. ${rec.course_name}</h3>
            <p class="course-description">${rec.description}</p>

            <div class="feedback-container">
                <h4 class="feedback-title">How helpful was this recommendation?</h4>
                <div class="star-rating" data-course-id="${courseId}">
                    <i class="fa-solid fa-star" data-rating="1"></i>
                    <i class="fa-solid fa-star" data-rating="2"></i>
                    <i class="fa-solid fa-star" data-rating="3"></i>
                    <i class="fa-solid fa-star" data-rating="4"></i>
                    <i class="fa-solid fa-star" data-rating="5"></i>
                </div>
                <textarea class="feedback-text" placeholder="Tell us more about your feedback (optional)"></textarea>
                <button class="feedback-submit">Submit Feedback</button>
                <div class="feedback-success">Thank you for your feedback!</div>
            </div>
        `;
        container.appendChild(card);
        setupStarRating(card);
    });

    initializeFeedbackHandlers();
}

function showErrorMessage() {
    const container = document.getElementById('recommendationsList');
    container.innerHTML = `
        <div class="no-results">
            <h3>Error loading recommendations</h3>
            <p>Please try again later or contact support.</p>
        </div>
    `;
}

function setupStarRating(card) {
    const stars = card.querySelectorAll('.star-rating i');
    let currentRating = 0;

    stars.forEach(star => {
        star.addEventListener('click', function () {
            const rating = parseInt(this.getAttribute('data-rating'));
            currentRating = rating;
            
            // Reset all stars
            stars.forEach(s => s.classList.remove('active'));
            
            // Activate selected stars
            for (let i = 0; i < rating; i++) {
                stars[i].classList.add('active');
            }

            // Store rating in parent element
            this.parentElement.setAttribute('data-selected-rating', rating);
        });

        // Hover effect
        star.addEventListener('mouseenter', function() {
            const hoverRating = parseInt(this.getAttribute('data-rating'));
            stars.forEach((s, i) => {
                if (i < hoverRating) {
                    s.classList.add('hover');
                } else {
                    s.classList.remove('hover');
                }
            });
        });

        star.addEventListener('mouseleave', function() {
            stars.forEach(s => s.classList.remove('hover'));
            // Restore current rating
            if (currentRating > 0) {
                for (let i = 0; i < currentRating; i++) {
                    stars[i].classList.add('active');
                }
            }
        });
    });
}

function initializeFeedbackHandlers() {
    const submitButtons = document.querySelectorAll('.feedback-submit');

    submitButtons.forEach(button => {
        button.addEventListener('click', function () {
            const feedbackContainer = this.closest('.feedback-container');
            const starRating = feedbackContainer.querySelector('.star-rating');
            const courseId = starRating.getAttribute('data-course-id');
            const rating = starRating.getAttribute('data-selected-rating');
            const comment = feedbackContainer.querySelector('.feedback-text').value;

            if (!rating) {
                alert('Please select a star rating before submitting.');
                return;
            }

            submitFeedback(courseId, rating, comment, feedbackContainer);
        });
    });
}

function submitFeedback(courseId, rating, comment, container) {
    const submitBtn = container.querySelector('.feedback-submit');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting...';
    
    // Simulate API call
    setTimeout(() => {
        const successMsg = container.querySelector('.feedback-success');
        successMsg.style.display = 'block';
        
        // Disable UI elements after submission
        container.querySelector('.star-rating').style.pointerEvents = 'none';
        container.querySelector('.feedback-text').disabled = true;
        submitBtn.style.display = 'none';
        
        // Reset button after success
        setTimeout(() => {
            successMsg.textContent = '✓ Feedback submitted successfully!';
        }, 1000);
        
        console.log('Feedback submitted:', { courseId, rating, comment });
    }, 1000);
}