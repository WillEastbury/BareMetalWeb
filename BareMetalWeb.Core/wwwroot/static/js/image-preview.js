// Image preview handler
document.addEventListener('DOMContentLoaded', function () {
    var fileInputs = document.querySelectorAll('input[type="file"].bm-upload-input, input[type="file"][accept*="image"]');
    var imageInputs = document.querySelectorAll('input[type="file"][accept*="image"]');

    fileInputs.forEach(function (input) {
        var maxSize = parseInt(input.getAttribute('data-max-size') || '0', 10);
        var wrapper = input.closest('.form-group, .mb-3, div');

        input.addEventListener('dragover', function (e) {
            e.preventDefault();
            if (wrapper) wrapper.classList.add('border', 'border-primary', 'rounded');
        });

        input.addEventListener('dragleave', function () {
            if (wrapper) wrapper.classList.remove('border', 'border-primary', 'rounded');
        });

        input.addEventListener('drop', function (e) {
            e.preventDefault();
            if (wrapper) wrapper.classList.remove('border', 'border-primary', 'rounded');
            if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                input.files = e.dataTransfer.files;
                input.dispatchEvent(new Event('change', { bubbles: true }));
            }
        });

        input.addEventListener('change', function () {
            if (maxSize > 0 && this.files && this.files[0] && this.files[0].size > maxSize) {
                this.value = '';
                alert('Selected file exceeds max allowed size.');
            }
        });
    });
    
    imageInputs.forEach(function (input) {
        // Find the corresponding preview element (should have id ending with _preview)
        var previewId = input.id + '_preview';
        var preview = document.getElementById(previewId);
        
        if (preview) {
            var currentObjectUrl = null;
            
            input.addEventListener('change', function () {
                // Revoke previous object URL to prevent memory leak
                if (currentObjectUrl) {
                    window.URL.revokeObjectURL(currentObjectUrl);
                    currentObjectUrl = null;
                }
                
                if (this.files && this.files[0]) {
                    currentObjectUrl = window.URL.createObjectURL(this.files[0]);
                    preview.src = currentObjectUrl;
                    preview.style.display = 'block';
                } else if (!preview.src) {
                    preview.style.display = 'none';
                }
            });
        }
    });
});
