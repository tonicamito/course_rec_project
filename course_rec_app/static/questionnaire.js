document.addEventListener('DOMContentLoaded', function () {
    const sections = document.querySelectorAll('.section');
    const progressBar = document.getElementById('progressBar');
    let currentSectionIndex = 0;

    initNavigation();
    initSubjectGrades();
    updateProgress();

    function initNavigation() {
        const navButtons = document.querySelectorAll('[id^="nextBtn"], [id^="prevBtn"]');
        
        navButtons.forEach(button => {
            button.addEventListener('click', function () {
                const isNext = this.id.startsWith('next');
                
                if (isNext && !validateCurrentSection()) return;
                
                currentSectionIndex = Math.max(0, Math.min(
                    currentSectionIndex + (isNext ? 1 : -1),
                    sections.length - 1
                ));

                showCurrentSection();
                updateProgress();
            });
        });
    }

    function showCurrentSection() {
        sections.forEach((section, index) => {
            const isActive = index === currentSectionIndex; 
            section.classList.toggle('active', isActive);
            
            // Update required fields only for active section
            section.querySelectorAll('[required]').forEach(field => {
                field.required = isActive;
            });
        });
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function updateProgress() {
        const progress = ((currentSectionIndex + 1) / sections.length) * 100;
        progressBar.style.width = `${progress}%`;

        document.querySelectorAll('[id^="prevBtn"]').forEach(btn => {
            btn.disabled = currentSectionIndex === 0;
        });
    }

    function validateCurrentSection() {
        const currentSection = sections[currentSectionIndex];
        let isValid = true;
    
        // 1. Validate required fields (text/number/email)
        const requiredInputs = currentSection.querySelectorAll(
            'input[required]:not([type="radio"]):not([type="checkbox"])'
        );
        requiredInputs.forEach(input => {
            if (!input.checkValidity()) {
                input.reportValidity();
                isValid = false;
            }
        });

        const radioGroups = Array.from(currentSection.querySelectorAll('input[type="radio"][required]'))
        .map(radio => radio.name)
        .filter((name, index, arr) => arr.indexOf(name) === index); 

    radioGroups.forEach(groupName => {
        const checked = currentSection.querySelector(`input[type="radio"][name="${groupName}"]:checked`);
        if (!checked) {
            isValid = false;
            alert(`Please select an option for: ${formatGroupName(groupName)}`);
        }
    });

    const checkboxGroups = Array.from(currentSection.querySelectorAll('input[type="checkbox"][required]'))
    .map(checkbox => checkbox.name)
    .filter((name, index, arr) => arr.indexOf(name) === index);

    checkboxGroups.forEach(groupName => {
        const checked = currentSection.querySelectorAll(`input[type="checkbox"][name="${groupName}"]:checked`);
        if (checked.length === 0) {
            isValid = false;
            alert(`Please select at least one option in: ${formatGroupName(groupName)}`);
        }
    });

    return isValid;
    }

    function formatGroupName(name) {
        return name
            .replace(/_/g, ' ')
            .replace(/(^\w|\s\w)/g, m => m.toUpperCase());
    }
    

    function initSubjectGrades() {
        const subjectContainer = document.querySelector('.subject-grades');
        const addButton = document.querySelector('.add-subject');
        const gradesDisplay = document.querySelector('.grades-display');

        if (!subjectContainer || !addButton || !gradesDisplay) {
            console.error("Error: One or more grade management elements are missing.");
            return;
        }

        addButton.addEventListener('click', function () {
            const subject = subjectContainer.querySelector('.subject-select').value;
            const grade = subjectContainer.querySelector('.grade-select').value;

            const existing = Array.from(gradesDisplay.querySelectorAll('.grade-item span'))
                .some(span => span.textContent.startsWith(subject));

            if (existing) {
                alert('This subject has already been added!');
                return;
            }

            const gradeItem = document.createElement('div');
            gradeItem.className = 'grade-item';
            gradeItem.innerHTML = `
                <span>${subject}: ${grade}</span>
                <button type="button" class="remove-grade">&times;</button>
                <input type="hidden" name="subject_grades[]" value="${subject}|${grade}">
            `;

            gradesDisplay.appendChild(gradeItem);
        });

        gradesDisplay.addEventListener('click', function (e) {
            if (e.target.classList.contains('remove-grade')) {
                e.target.closest('.grade-item').remove();
            }
        });
    }

    document.getElementById('majorQuestionnaire').addEventListener('submit', async function (e) {
        e.preventDefault();
        
        if (!validateCurrentSection()) return;

        const formData = new FormData(this);
      
        const subjectGrades = [];
        formData.getAll('subject_grades[]').forEach(pair => {
            const [subject, grade] = pair.split('|');
            subjectGrades.push({ subject, grade });
            });

            const data = {
                kcse_grade: formData.get('kcse_grade'),
                best_subjects: formData.getAll('best_subjects'),
                subject_grades: Array.from(formData.getAll('subject_grades[]')).map(pair => {
                    const [subject, grade] = pair.split('|');
                    return { subject, grade }; 
                }),
                work_sector: formData.getAll('work_sector')
            };

        [
            'critical_thinking', 'numbers_data', 'social_problems',
            'teaching_helping', 'different_cultures', 'environmental_issues',
            'global_politics', 'interacting_with_people', 'religious_spiritual',
            'scientific_research', 'organizing_information', 'public_speaking',
            'high_pressure', 'helping_others', 'working_preference',
            'collaboration_preference', 'problem_solving', 'career_values',
            'further_studies', 'problem_approach'
        ].forEach(key => {
            const value = formData.get(key);
            if (value) data[key] = value;
        });

        try {
            const response = await fetch('/recommend', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include', 
                body: JSON.stringify(data)
            });

            if (response.status === 401) {
                alert("Session expired. Please log in again.");
                localStorage.removeItem('authToken');
                window.location.href = '/login';
                return;
            }

            if (response.status === 400) {
                const errorData = await response.json();
                alert(errorData.error || "Invalid submission. Please check your inputs.");
                return;
            }

            if (!response.ok) {
                throw new Error(`Server error: ${response.status}`);
            }
            
            if (response.ok) {
                const result = await response.json();
                window.location.href = '/results';
            }

        } catch (error) {
            console.error("Error submitting questionnaire:", error.message);
            alert("Something went wrong. Please try again.");
        }
    });
});


  
