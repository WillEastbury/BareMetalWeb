// Image preview handler
document.addEventListener('DOMContentLoaded', function () {
    // Find all file inputs that accept images
    var imageInputs = document.querySelectorAll('input[type="file"][accept*="image"]');
    
    imageInputs.forEach(function (input) {
        // Find the corresponding preview element (should have id ending with _preview)
        var previewId = input.id + '_preview';
        var preview = document.getElementById(previewId);
        
        if (preview) {
            input.addEventListener('change', function () {
                if (this.files && this.files[0]) {
                    preview.src = window.URL.createObjectURL(this.files[0]);
                }
            });
        }
    });
});
