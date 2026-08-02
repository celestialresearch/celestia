// Copyright © 2026 @sudocelestia. All rights reserved.
//
// PROPRIETARY AND CONFIDENTIAL SOURCE CODE.
//
// No licence, permission or authorisation is granted to use, copy, modify,
// compile, execute, distribute, publish, sublicense or otherwise exploit this
// file, except to the limited extent unavoidably permitted by applicable law
// or GitHub's Terms of Service.
//
// See the LICENSE file at the repository root for the complete terms.

//go:build windows && amd64

package supervision

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

type launchResources struct {
	container appContainer
	image     *os.File
	imagePath string
	imageHash [32]byte
	pipes     pipeSet
	job       windows.Handle
	cleanup   time.Duration
}

type launchPreparationOperations struct {
	createContainer func() (appContainer, error)
	stageImage      func(string, string) (*os.File, [32]byte, string, bool, error)
	newPipes        func() (pipeSet, bool, error)
	createJob       func(Limits) (windows.Handle, bool, error)
}

func defaultLaunchPreparationOperations() launchPreparationOperations {
	return launchPreparationOperations{
		createContainer: createContainerName,
		stageImage:      stageImage,
		newPipes:        newPipes,
		createJob:       createJob,
	}
}

func (supervisor *Supervisor) launch(
	ctx context.Context,
	startupDeadline time.Time,
) (*launchedProcess, [32]byte, bool, error) {
	resources, cleanupComplete, err := supervisor.prepareLaunch(ctx, startupDeadline)
	if err != nil {
		return nil, [32]byte{}, cleanupComplete, err
	}
	process, cleanupComplete, err := resources.start(ctx, startupDeadline)
	if err != nil {
		closeErr := resources.close()
		return nil,
			resources.imageHash,
			cleanupSucceeded(cleanupComplete, closeErr),
			errors.Join(err, closeErr)
	}
	return process, resources.imageHash, true, nil
}

func (supervisor *Supervisor) prepareLaunch(
	ctx context.Context,
	startupDeadline time.Time,
) (*launchResources, bool, error) {
	return supervisor.prepareLaunchWith(ctx, startupDeadline, defaultLaunchPreparationOperations())
}

func (supervisor *Supervisor) prepareLaunchWith(
	ctx context.Context,
	startupDeadline time.Time,
	operations launchPreparationOperations,
) (*launchResources, bool, error) {
	container, err := operations.createContainer()
	if err != nil {
		if container.name != "" {
			cleanupErr := container.close()
			return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
		}
		return nil, true, err
	}
	if err := checkStartupContext(ctx, startupDeadline); err != nil {
		cleanupErr := container.close()
		return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
	}
	image, hash, imagePath, imageCleanupComplete, err := operations.stageImage(
		container.folder,
		supervisor.workerPath,
	)
	if err != nil {
		cleanupErr := container.close()
		return nil,
			cleanupSucceeded(imageCleanupComplete, cleanupErr),
			errors.Join(err, cleanupErr)
	}
	if err := checkStartupContext(ctx, startupDeadline); err != nil {
		cleanupErr := errors.Join(image.Close(), container.close())
		return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
	}
	if hash != supervisor.workerHash {
		cleanupErr := errors.Join(image.Close(), container.close())
		return nil,
			cleanupErr == nil,
			errors.Join(errors.New("configured worker identity changed"), cleanupErr)
	}
	pipes, pipeCleanupComplete, err := operations.newPipes()
	if err != nil {
		cleanupErr := errors.Join(image.Close(), container.close())
		return nil,
			cleanupSucceeded(pipeCleanupComplete, cleanupErr),
			errors.Join(err, cleanupErr)
	}
	if err := checkStartupContext(ctx, startupDeadline); err != nil {
		cleanupErr := errors.Join(pipes.close(), image.Close(), container.close())
		return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
	}
	job, jobCleanupComplete, err := operations.createJob(supervisor.limits)
	if err != nil {
		cleanupErr := errors.Join(pipes.close(), image.Close(), container.close())
		return nil,
			cleanupSucceeded(jobCleanupComplete, cleanupErr),
			errors.Join(err, cleanupErr)
	}
	resources := &launchResources{
		container: container,
		image:     image,
		imagePath: imagePath,
		imageHash: hash,
		pipes:     pipes,
		job:       job,
		cleanup:   supervisor.limits.CleanupTimeout,
	}
	return finishLaunchPreparation(ctx, resources, startupDeadline)
}

func finishLaunchPreparation(
	ctx context.Context,
	resources *launchResources,
	startupDeadline time.Time,
) (*launchResources, bool, error) {
	if err := checkStartupContext(ctx, startupDeadline); err != nil {
		cleanupErr := resources.close()
		return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
	}
	return resources, true, nil
}

func createContainerName() (appContainer, error) {
	return createContainerNameWith(rand.Reader, createContainer)
}

func createContainerNameWith(
	randomSource io.Reader,
	create func(string) (appContainer, error),
) (appContainer, error) {
	var random [16]byte
	if _, err := io.ReadFull(randomSource, random[:]); err != nil {
		return appContainer{}, fmt.Errorf("generate AppContainer identity: %w", err)
	}
	return create("celestia.worker." + hex.EncodeToString(random[:]))
}
