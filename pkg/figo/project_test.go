package figo

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_NewProjectFromDicts(t *testing.T) {
	Convey("Create new project from a list of dicts representing services", t, func() {
		dicts := map[string]map[string]interface{}{
			"web": map[string]interface{}{
				"name":  "web",
				"image": "busybox:latest",
			},
			"db": map[string]interface{}{
				"name":  "db",
				"image": "busybox:latest",
			},
		}
		pro, err := NewProjectFromDicts("figotest", dicts, nil)
		So(err, ShouldBeNil)

		Convey("Get all services of project", func() {
			services, err := pro.GetServices(nil, false)
			So(err, ShouldBeNil)
			So(len(services), ShouldEqual, 2)
		})

		Convey("Get service by name", func() {
			for _, name := range []string{"web", "db"} {
				s, err := pro.GetService(name)
				So(err, ShouldBeNil)
				So(s.name, ShouldEqual, name)
				So(s.options["image"], ShouldEqual, "busybox:latest")
			}
		})
	})

	Convey("Make sure create from dicts dependency order is correct", t, func() {
		dicts := map[string]map[string]interface{}{
			"web": map[string]interface{}{
				"name":  "web",
				"image": "busybox:latest",
				"links": []interface{}{"db"},
			},
			"db": map[string]interface{}{
				"name":         "db",
				"image":        "busybox:latest",
				"volumes_from": []interface{}{"volume"},
			},
			"volume": map[string]interface{}{
				"name":  "volume",
				"image": "busybox:latest",
			},
		}
		pro, err := NewProjectFromDicts("figotest", dicts, nil)
		So(err, ShouldBeNil)

		names := []string{"volume", "db", "web"}
		for i, s := range pro.services {
			So(s.name, ShouldEqual, names[i])
		}
	})
}

func Test_NewProjectFromConfig(t *testing.T) {
	Convey("Create new project from configuration", t, func() {
		dicts := map[string]map[string]interface{}{
			"web": map[string]interface{}{
				"image": "busybox:latest",
			},
			"db": map[string]interface{}{
				"image": "busybox:latest",
			},
		}
		pro, err := NewProjectFromConfig("figotest", dicts, nil)
		So(err, ShouldBeNil)

		Convey("Get all services of project", func() {
			services, err := pro.GetServices(nil, false)
			So(err, ShouldBeNil)
			So(len(services), ShouldEqual, 2)
		})

		Convey("Get service by name", func() {
			for _, name := range []string{"web", "db"} {
				s, err := pro.GetService(name)
				So(err, ShouldBeNil)
				So(s.name, ShouldEqual, name)
				So(s.options["image"], ShouldEqual, "busybox:latest")
			}
		})
	})
}

func Test_Project_GetService(t *testing.T) {
	Convey("Retrieve a service from project by name", t, func() {
		web := NewService("web", nil, "figotest", nil, nil, map[string]interface{}{"image": "busybox:latest"})
		pro := NewProject("test", []*Service{web}, nil)
		s, err := pro.GetService("web")
		So(err, ShouldBeNil)
		So(s, ShouldEqual, web)
	})
}

func Test_Project_GetServices(t *testing.T) {
	Convey("Get all services without argument", t, func() {
		web := NewService("web", nil, "figotest", nil, nil, nil)
		console := NewService("console", nil, "figotest", nil, nil, nil)
		list := []*Service{web, console}
		pro := NewProject("test", list, nil)
		services, err := pro.GetServices(nil, false)
		So(err, ShouldBeNil)

		for i, s := range services {
			So(s, ShouldEqual, list[i])
		}
	})

	Convey("Get all services with argument", t, func() {
		web := NewService("web", nil, "figotest", nil, nil, nil)
		console := NewService("console", nil, "figotest", nil, nil, nil)
		pro := NewProject("test", []*Service{web, console}, nil)
		services, err := pro.GetServices([]string{"console"}, false)
		So(err, ShouldBeNil)
		So(services[0], ShouldEqual, console)
	})

	Convey("Get all services with links", t, func() {
		db := NewService("db", nil, "figotest", nil, nil, nil)
		web := NewService("web", nil, "figotest", map[string]Link{"db": {db, "db"}}, nil, nil)
		cache := NewService("cache", nil, "figotest", nil, nil, nil)
		console := NewService("console", nil, "figotest", map[string]Link{"web": {web, "web"}}, nil, nil)
		pro := NewProject("test", []*Service{web, db, cache, console}, nil)
		services, err := pro.GetServices([]string{"console"}, true)
		So(err, ShouldBeNil)
		So(services[0], ShouldEqual, console)
		So(services[1], ShouldEqual, web)
		So(services[2], ShouldEqual, db)
	})

	Convey("Get all services handles duplicated following links", t, func() {
		db := NewService("db", nil, "figotest", nil, nil, nil)
		web := NewService("web", nil, "figotest", map[string]Link{"db": {db, "db"}}, nil, nil)
		pro := NewProject("test", []*Service{web, db}, nil)
		services, err := pro.GetServices([]string{"web", "db"}, true)
		So(err, ShouldBeNil)
		So(services[0], ShouldEqual, web)
		So(services[1], ShouldEqual, db)
	})
}
