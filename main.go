package main

import (
	"bufio"
	"context"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/grafov/m3u8"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

var store sessions.Store
var idTokenValidator *idtoken.Validator

var watchingLock *sync.Map
var channels map[int]Channel

func main() {
	loadChannelList()

	r := gin.Default()

	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

	r.LoadHTMLGlob("static/templates/*")

	r.POST("/login", login)
	r.POST("/logout", logout)
	r.GET("/dashboard", AuthRequired(), getDashboard)
	r.GET("/streaming/:channelId", AuthRequired(), videoProxy)
	r.GET("/api/channels", AuthRequired(), getChannels)
	r.GET("/", getHomePage)

	watchingLock = &sync.Map{}

	// static files
	r.Static("/static", "static")

	idTokenValidator, _ = idtoken.NewValidator(context.Background(), option.WithoutAuthentication())

	_ = r.Run(":8080")
}

func videoProxy(c *gin.Context) {
	user, _ := c.Get("user")
	email := user.(User).Email
	if watching, ok := watchingLock.Load(email); ok && watching.(bool) {
		c.JSON(http.StatusForbidden, gin.H{"error": "only 1 streaming allowed"})
		return
	}

	id, err := strconv.Atoi(c.Param("channelId"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No such channel"})
		return
	}
	channel, ok := channels[id]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "No such channel"})
		return
	}

	remote, err := url.Parse(strings.Replace(channel.Url, "udp://@", os.Getenv("UDPXY_URL"), -1))
	if err != nil {
		panic(err)
	}

	proxy := NewSingleHostReverseProxy(remote)
	proxy.Director = func(req *http.Request) {
		req.Header = c.Request.Header
		req.Host = remote.Host
		req.URL.Scheme = remote.Scheme
		req.URL.Host = remote.Host
		req.URL.Path = remote.Path
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		log.Printf("%s Streaming stopped.", email)
		watchingLock.Store(email, false)
	}

	log.Printf("Starting streaming channel #%03d for %s", channel.Id, user.(User).Email)

	watchingLock.Store(email, true)

	proxy.ServeHTTP(c.Writer, c.Request)

	watchingLock.Store(email, false)
}

func loadChannelList() {
	channels = make(map[int]Channel)
	f, err := os.Open("playlist.m3u8")
	if err != nil {
		panic(err)
	}
	p, _, err := m3u8.DecodeFrom(bufio.NewReader(f), false)
	if err != nil {
		panic(err)
	}

	playlists := p.(*m3u8.MediaPlaylist)

	for i := 0; i < int(playlists.Count()); i++ {
		title := strings.Split(playlists.Segments[i].Title, " - ")
		id, _ := strconv.Atoi(title[0])

		channels[id] = Channel{
			Name: title[1],
			Id:   id,
			Url:  playlists.Segments[i].URI,
		}
	}
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := store.Get(c.Request, "session")
		if err != nil {
			if strings.Index(c.Request.URL.Path, "/api") != 0 {
				c.Redirect(http.StatusTemporaryRedirect, "/")
				c.Abort()
				return
			}

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session data corrupted"})
			return
		}
		if session.Values["email"] == nil {

			if strings.Index(c.Request.URL.Path, "/api") != 0 {
				c.Redirect(http.StatusTemporaryRedirect, "/")
				c.Abort()
				return
			}

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "login required"})
			return
		}

		c.Set("user", User{
			Email: session.Values["email"].(string),
		})

		c.Next()
	}
}

func getDashboard(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{"clientId": os.Getenv("CLIENT_ID")})
}

func getHomePage(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{"clientId": os.Getenv("CLIENT_ID")})
}

func logout(c *gin.Context) {
	session, _ := store.Get(c.Request, "session")
	session.Options.MaxAge = -1
	_ = session.Save(c.Request, c.Writer)
	c.Redirect(http.StatusFound, "/")
}

func login(c *gin.Context) {
	var loginRequest LoginRequest
	err := c.BindJSON(&loginRequest)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
		return
	}

	token, err := idTokenValidator.Validate(context.Background(), loginRequest.IdToken, os.Getenv("CLIENT_ID"))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := token.Claims["email"].(string)
	validEmail := false

	for _, u := range getUserList() {
		if u.Email == email {
			validEmail = true
			break
		}
	}
	if !validEmail {
		c.JSON(http.StatusForbidden, gin.H{"error": "This thing is not for you ~"})
		return
	}

	session, err := store.New(c.Request, "session")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	session.Values["email"] = token.Claims["email"]

	_ = session.Save(c.Request, c.Writer)

	c.JSON(http.StatusOK, gin.H{"email": token.Claims["email"], "name": token.Claims["name"]})
}

func getChannels(c *gin.Context) {
	c.JSON(http.StatusOK, channels)
}

func getUserList() []User {
	var lists []User
	f, _ := os.Open("lists.yaml")
	defer f.Close()
	b, _ := io.ReadAll(f)
	_ = yaml.Unmarshal(b, &lists)
	return lists
}
