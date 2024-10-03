# How to contribute and make changes to your user image

## Setting up your fork and clones
First, go to your [github profile settings](https://github.com/settings/keys)
and make sure you have an SSH key uploaded.

Next, go to the github repo of the image that you'd like to work on and create
a fork.  To do this, click on the `fork` button and then `Create fork`.

![Forking](images/create-fork.png)


After you create your fork of the new image repository, you should disable Github Actions **only for your fork**.  To do this, navigate to `Settings` --> `Actions` --> `General` and select `Disable actions`.  Then click `Save`:

![Disable fork actions](images/disable-fork-actions.png)

Now clone the primary image repo on your local device.  You can get the URL to do
this by clicking on the green `Code` button in the primary image repo (*not* your fork)
and clicking on `SSH` and copying the text located therein:

![Remote](images/remote.png)

Now `cd` in to a handy folder on your device, and clone the primary repo by
running the following command (replace `<image-name>` with the actual name
of the image):

```
git clone git@github.com:berkeley-dsep-infra/<image-name>.git
```

Now `cd` in to `<image-name>` and set up your local repo to point both at the primary
image repo (`upstream`) and your fork (`origin`).  After the initial clone,
`origin` will be pointing to the main repo and we'll need to change that.

```
$ cd <image-name>
$ git remote -v # confirm that origin points to the primary repo
origin	git@github.com:berkeley-dsep-infra/<image-name>.git (fetch)
origin	git@github.com:berkeley-dsep-infra/<image-name>.git (push)
$ git remote rename origin upstream # rename origin to upstream
$ git remote add origin git@github.com:<your github username>/<image-name>.git # add your fork as origin
$ git remote -v # confirm the settings
origin	git@github.com:<your github username>/<image-name>.git (fetch)
origin	git@github.com:<your github username>/<image-name>.git (push)
upstream	git@github.com:berkeley-dsep-infra/<image-name>.git (fetch)
upstream	git@github.com:berkeley-dsep-infra/<image-name>.git (push)
```

Now you can sync your local repo from `upstream`, and push those changes to your
fork (`origin`):

```
git checkout main && \
git fetch --prune --all && \
git rebase upstream/main && \
git push origin main
```

## Procedure

When developing for this deployment, always work in a fork of this repo.
You should also make sure that your repo is up-to-date with this one prior
to making changes. This is because other contributors may have pushed changes
after you last synced with this repo but before you upstreamed your changes.

```
git checkout main && \
git fetch --prune --all && \
git rebase upstream/main && \
git push origin main
```

To create a new feature branch and switch to it, run the following command:

```
git checkout -b <branch name>
```

After you make your changes, you can use the following commands to see
what's been modified and check out the diffs:  `git status` and `git diff`.

### Building the image locally

You should use [repo2docker](https://repo2docker.readthedocs.io/en/latest/) to build and use/test the image on your own device before you push and create a PR.  It's better (and typically faster) to do this first before using CI/CD.  There's no need to waste Github Action minutes to test build images when you can do this on your own device!

Run `repo2docker` from inside the cloned image repo.  To run on a linux/WSL2 linux shell:
```
repo2docker . # <--- the path to the repo
```

If you are using an ARM CPU (Apple M* silicon), you will need to run `jupyter-repo2docker` with the following arguments:

```
jupyter-repo2docker --user-id=1000 --user-name=jovyan \
  --Repo2Docker.platform=linux/amd64 \
  --target-repo-dir=/home/jovyan/.cache \
  -e PLAYWRIGHT_BROWSERS_PATH=/srv/conda \
  . # <--- the path to the repo
```

If you just want to see if the image builds, but not automatically launch the server, add `--no-run` to the arguments (before the final `.`).

When you're ready to push these changes, first you'll need to stage them for a
commit:

```
git add <file1> <file2> <etc>
```

Commit these changes locally:

```
git commit -m "some pithy commit description"
```

Now push to your fork:

```
git push origin <branch name>
```

Once you've pushed to your fork, you can go to the image repo and there should
be a big green button on the top that says `Compare and pull request`.
Click on that, check out the commits and file diffs, edit the title and
description if needed and then click `Create pull request`.

![Compare and create PR](images/compare-and-create-pr.png)

![Create PR](images/create-pr.png)

If you're having issues, you can refer to the [github documentation for pull
requests](https://help.github.com/articles/about-pull-requests/).
Keep the choice for `base` in the GitHub PR user interface, while the choice
for `head` is your fork.

Once this is complete and if there are no problems, a github action will
automatically [build and test](https://github.com/berkeley-dsep-infra/hub-user-image-template/blob/main/.github/workflows/build-test-image.yaml)
the image.  If this fails, please check the output of the workflow in the
action, and make any changes required to get the build to pass.

Once the image build has completed successfully, you can request that
someone review the PR before merging, or you can merge yourself if you are
confident. This merge will trigger a [second giuthub workflow](https://github.com/berkeley-dsep-infra/hub-user-image-template/blob/main/.github/workflows/build-push-image-commit.yaml)
that builds the image again, pushes it to the appropriate location in our
Google Artifact Registry and finally creates and pushes a commit to the
[Datahub](https://github.com/berkeley-dsep-infra/datahub) repo updating the
image hash of the deployment to point at the newly built image.

You will now need to create a pull request in the Datahub repo to merge these changes
and deploy them to `staging` for testing.
