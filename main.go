package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

type User struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirmPassword"`
}

var users []User

func main() {
	e := echo.New()

	file, err := CheckDataFile()
	if err != nil {
		fmt.Println(err)
		return
	}

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello")
	})

	e.POST("/signup", func(c echo.Context) error {
		user := new(User)
		if err := c.Bind(user); err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		if (user.Password != user.ConfirmPassword) {
			return c.String(http.StatusBadRequest, "Password and Confirm Password is not match")
		}

		// check username if alphabet and number only, use regex
		pattern := "^[a-zA-Z0-9]*$"
		test := regexp.MustCompile(pattern)
		if !test.MatchString(user.Username) {
			return c.String(http.StatusBadRequest, "Username must be alphabet and number only")
		}
		
		for i := 0; i < len(users); i++ {
			if (users[i].Username == user.Username) {
				return c.String(http.StatusBadRequest, "Username is exist")
			}
		}

		jsonData, err := json.Marshal(user)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		// write the data in file in new line
		_, err = file.Write(append(jsonData, '\n'))
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}
		
		var userdata User
		err = json.Unmarshal(jsonData, &userdata)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		users = append(users, userdata)

		resData, err := json.Marshal(users)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		return c.String(http.StatusOK, string(resData))
	})

	e.POST("/login", func(c echo.Context) error {
		user := new(User)
		if err := c.Bind(user); err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		// loop to all users to check if username is exist, if not return error, if exist check password
		for i := 0; i < len(users); i++ {
			if (users[i].Username == user.Username) {
				if (users[i].Password == user.Password) {

					// create login auth token
					token := jwt.New(jwt.SigningMethodHS256)
					claims := token.Claims.(jwt.MapClaims)
					claims["name"] = user.Username
					claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

					t, err := token.SignedString([]byte("secret"))
					if err != nil {
						return c.String(http.StatusBadRequest, err.Error())
					}

					// return token
					return c.String(http.StatusOK, t)
				} else {
					return c.String(http.StatusBadRequest, "Password is wrong")
				}
			}
		}

		return c.String(http.StatusBadRequest, "Username is not exist")
	})

	e.Logger.Fatal(e.Start(":3000"))
}

func CheckDataFile() (*os.File, error) {
	file, err := os.OpenFile("data.txt",  os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	// read data from file, if EOF, return continue
	data := make([]byte, 1024)
	count, _ := file.Read(data)
	// if err != nil {
	// 	// return nil, err
	// }

	// if data is exist, parse to json
	if count > 0 {
		// {"username":"user2","password":"pass1","confirmPassword":"pass1"}
		// data is in json format and separated by new line
		// split data by new line
		lines := string(data[:count])
		usersData := regexp.MustCompile("\n").Split(lines, -1)
		for i := 0; i < len(usersData); i++ {
			var user User
			if usersData[i] == "" {
				continue
			}
			err = json.Unmarshal([]byte(usersData[i]), &user)
			if err != nil {
				return nil, err
			}
			users = append(users, user)
		}
	}

	return file, nil
}