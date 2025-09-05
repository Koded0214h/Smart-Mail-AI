from django import forms
from .models import Profile

class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['filters']
        widgets = {
            'filters': forms.TextInput(attrs={'placeholder': 'e.g. finance, work, promotions'})
        }
