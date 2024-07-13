package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"

	"github.com/go-playground/validator"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type SignupUser struct {
	User
	ConfirmPassword string `json:"confirm_password" validate:"required"`
}

type CustomValidator struct {
	validator *validator.Validate
}

var users []User

const DATA_FILE = "data.json"

func main() {
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}

	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))

	_, err := CheckDataFile()
	if err != nil {
		fmt.Println(err)
	}

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello")
	})

	e.POST("/signup", func(c echo.Context) error {
		user := new(SignupUser)
		if err := c.Bind(user); err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		err := c.Validate(user)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		if user.Password != user.ConfirmPassword {
			return c.String(http.StatusBadRequest, "Password and Confirm Password is not match")
		}

		// check username if alphabet and number only, use regex
		pattern := "^[a-zA-Z0-9]*$"
		test := regexp.MustCompile(pattern)
		if !test.MatchString(user.Username) {
			return c.String(http.StatusBadRequest, "Username must be alphabet and number only")
		}

		for i := 0; i < len(users); i++ {
			if users[i].Username == user.Username {
				return c.String(http.StatusBadRequest, "Username is exist")
			}
		}

		// hash password
		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		user.Password = string(hash)

		jsonData, err := json.Marshal(user)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		var userdata User
		err = json.Unmarshal(jsonData, &userdata)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		users = append(users, userdata)

		err = SaveDataToFile(users)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		log.Println("User: ", user.Username, " is created successfully")

		return c.String(http.StatusOK, string("User: "+user.Username+" is created successfully"))
	})

	e.POST("/login", func(c echo.Context) error {
		user := new(User)
		if err := c.Bind(user); err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		err := c.Validate(user)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		// loop to all users to check if username is exist, if not return error, if exist check password
		for i := 0; i < len(users); i++ {
			if users[i].Username == user.Username {

				// check password
				err := bcrypt.CompareHashAndPassword([]byte(users[i].Password), []byte(user.Password))
				if err != nil {
					return c.String(http.StatusBadRequest, "Password is wrong")
				}

				sess, err := session.Get("session", c)
				if err != nil {
					return err
				}
				sess.Options = &sessions.Options{
					Path:     "/",
					MaxAge:   86400 * 7,
					HttpOnly: true,
				}
				sess.Values["username"] = user.Username
				if err := sess.Save(c.Request(), c.Response()); err != nil {
					return err
				}

				log.Println("User: ", user.Username, " is logged in successfully")

				return c.String(http.StatusOK, "User: "+user.Username+" is logged in successfully")
			}
		}

		return c.String(http.StatusBadRequest, "Username is not exist")
	})

	e.POST("/logout", func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil {
			return err
		}

		sess.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		}

		if err := sess.Save(c.Request(), c.Response()); err != nil {
			return err
		}

		return c.String(http.StatusOK, "Logout successfully")
	})

	// define route to get all users (protected by session)
	e.GET("/users", func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil {
			return err
		}

		username := sess.Values["username"]
		if username == nil {
			return c.String(http.StatusBadRequest, "Unauthorized")
		}

		var usersData []User
		for i := 0; i < len(users); i++ {
			usersData = append(usersData, User{Username: users[i].Username, Password: "<hidden>"})
		}

		return c.JSON(http.StatusOK, usersData)
	})

	e.Logger.Fatal(e.Start(":3000"))
}

func CheckDataFile() (*os.File, error) {
	file, err := os.OpenFile(DATA_FILE, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var usersData []User
	err = json.Unmarshal(data, &usersData)
	if err != nil {
		return nil, err
	}

	users = usersData

	return file, nil
}

func SaveDataToFile(users []User) error {
	file, err := os.OpenFile(DATA_FILE, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	jsonUsers, err := json.MarshalIndent(users, "", "    ")
	if err != nil {
		return err
	}

	_, err = file.Write(jsonUsers)
	if err != nil {
		return err
	}

	return nil
}

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}
