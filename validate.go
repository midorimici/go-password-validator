package passwordvalidator

import (
	"errors"
	"fmt"
	"strings"
)

// Validate returns nil if the password has greater than or
// equal to the minimum entropy. If not, an error is returned
// that explains how the password can be strengthened. This error
// is safe to show the client
func Validate(password string, minEntropy float64) error {
	entropy := getEntropy(password)
	if entropy >= minEntropy {
		return nil
	}

	hasReplace, hasSep, hasOtherSpecial, hasLower, hasUpper, hasDigits := getCharacterContainment(password)

	allMessages := []string{}

	if !hasOtherSpecial || !hasSep || !hasReplace {
		allMessages = append(allMessages, "including more special characters")
	}
	if !hasLower {
		allMessages = append(allMessages, "using lowercase letters")
	}
	if !hasUpper {
		allMessages = append(allMessages, "using uppercase letters")
	}
	if !hasDigits {
		allMessages = append(allMessages, "using numbers")
	}

	if len(allMessages) > 0 {
		return fmt.Errorf(
			"insecure password, try %v or using a longer password",
			strings.Join(allMessages, ", "),
		)
	}

	return errors.New("insecure password, try using a longer password")
}

var (
	// ErrInsufficientSpecialCharacters is returned when the password does not contain enough variety of special characters.
	ErrInsufficientSpecialCharacters = errors.New("special characters are not used enough")
	// ErrNoLowercaseLetters is returned when the password does not contain any lowercase letters.
	ErrNoLowercaseLetters = errors.New("no lowercase letters are used")
	// ErrNoUppercaseLetters is returned when the password does not contain any uppercase letters.
	ErrNoUppercaseLetters = errors.New("no uppercase letters are used")
	// ErrNoDigits is returned when the password does not contain any digits.
	ErrNoDigits = errors.New("no digits are used")
	// ErrShortPassword is returned when the password is too short.
	ErrShortPassword = errors.New("password is too short")
)

// ValidateWithErrorSlice is similar to Validate but returns
// a slice of errors that explain the issues with the password.
// When the password is strong enough, it returns nil.
// This function is useful for returning multiple errors separately.
func ValidateWithErrorSlice(password string, minEntropy float64) []error {
	entropy := getEntropy(password)
	if entropy >= minEntropy {
		return nil
	}

	hasReplace, hasSep, hasOtherSpecial, hasLower, hasUpper, hasDigits := getCharacterContainment(password)

	errs := []error{}

	if !hasOtherSpecial || !hasSep || !hasReplace {
		errs = append(errs, ErrInsufficientSpecialCharacters)
	}
	if !hasLower {
		errs = append(errs, ErrNoLowercaseLetters)
	}
	if !hasUpper {
		errs = append(errs, ErrNoUppercaseLetters)
	}
	if !hasDigits {
		errs = append(errs, ErrNoDigits)
	}

	if len(errs) == 0 {
		return []error{ErrShortPassword}
	}

	errs = append(errs, ErrShortPassword)
	return errs
}

func getCharacterContainment(password string) (hasReplace, hasSep, hasOtherSpecial, hasLower, hasUpper, hasDigits bool) {
	for _, c := range password {
		switch {
		case strings.ContainsRune(replaceChars, c):
			hasReplace = true
		case strings.ContainsRune(sepChars, c):
			hasSep = true
		case strings.ContainsRune(otherSpecialChars, c):
			hasOtherSpecial = true
		case strings.ContainsRune(lowerChars, c):
			hasLower = true
		case strings.ContainsRune(upperChars, c):
			hasUpper = true
		case strings.ContainsRune(digitsChars, c):
			hasDigits = true
		}
	}

	return
}
