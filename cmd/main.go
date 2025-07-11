package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crewcrew23/dnssniffer/internal/core"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := cli.Command{
		Name:  "dnslogger",
		Usage: "log dns requests",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "i",
				Usage:    "name of network interface",
				Required: false,
			},
			&cli.BoolFlag{
				Name:     "list",
				Usage:    "display list available network interfaces",
				Required: false,
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			list := c.Bool("list")
			netInterface := c.String("i")

			if list {
				core.ListInterfaces()
				return nil
			}

			if err := core.Start(netInterface); err != nil {
				return err
			}
			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
	}
}
