package passwordvalidator

import (
	"testing"
)

func TestValidate(t *testing.T) {
	err := Validate("mypass", 50)
	expectedError := "insecure password, try including more special characters, using uppercase letters, using numbers or using a longer password"
	if err.Error() != expectedError {
		t.Errorf("Wanted %v, got %v", expectedError, err)
	}

	err = Validate("MYPASS", 50)
	expectedError = "insecure password, try including more special characters, using lowercase letters, using numbers or using a longer password"
	if err.Error() != expectedError {
		t.Errorf("Wanted %v, got %v", expectedError, err)
	}

	err = Validate("mypassword", 4)
	if err != nil {
		t.Errorf("Err should be nil")
	}

	err = Validate("aGoo0dMi#oFChaR2", 80)
	if err != nil {
		t.Errorf("Err should be nil")
	}

	expectedError = "insecure password, try including more special characters, using lowercase letters, using uppercase letters or using a longer password"
	err = Validate("123", 60)
	if err.Error() != expectedError {
		t.Errorf("Wanted %v, got %v", expectedError, err)
	}
}

func TestValidateWithErrorSlice(t *testing.T) {
	errs := ValidateWithErrorSlice("mypass", 50)
	expectedErrors := []error{ErrInsufficientSpecialCharacters, ErrNoUppercaseLetters, ErrNoDigits, ErrShortPassword}
	testErrorSlice(t, errs, expectedErrors)

	errs = ValidateWithErrorSlice("MYPASS", 50)
	expectedErrors = []error{ErrInsufficientSpecialCharacters, ErrNoLowercaseLetters, ErrNoDigits, ErrShortPassword}
	testErrorSlice(t, errs, expectedErrors)

	errs = ValidateWithErrorSlice("mypassword", 4)
	if errs != nil {
		t.Errorf("Errs should be nil")
	}

	errs = ValidateWithErrorSlice("aGoo0dMi#oFChaR2", 80)
	if errs != nil {
		t.Errorf("Errs should be nil")
	}

	expectedErrors = []error{ErrInsufficientSpecialCharacters, ErrNoLowercaseLetters, ErrNoUppercaseLetters, ErrShortPassword}
	errs = ValidateWithErrorSlice("123", 60)
	testErrorSlice(t, errs, expectedErrors)
}

func testErrorSlice(t *testing.T, errs []error, expectedErrors []error) {
	t.Helper()

	if len(errs) != len(expectedErrors) {
		t.Errorf("Wanted %v, got %v", expectedErrors, errs)
		return
	}

	for i, err := range errs {
		expectedError := expectedErrors[i]
		if err.Error() != expectedError.Error() {
			t.Errorf("Errs[%d]: Wanted %v, got %v", i, expectedError, err)
		}
	}
}
