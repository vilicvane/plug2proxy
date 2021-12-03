export type BatchSchedulerHandler<T> = (tasks: T[]) => Promise<void> | void;

/**
 * BatchScheduler provides the ability to handle tasks scheduled within a time
 * span in batch.
 */
export class BatchScheduler<T> {
  private tasks: T[] = [];

  private batchPromise: Promise<void> | undefined;

  /**
   * Construct a BatchScheduler instance.
   *
   * @param handler A batch handler for the tasks put together.
   * @param timeBeforeStart The time span within which tasks would be handled
   * in batch.
   */
  constructor(
    private handler: BatchSchedulerHandler<T>,
    private timeBeforeStart?: number,
  ) {}

  /** Schedule a task. */
  async schedule(...args: void extends T ? [] : [task: T]): Promise<void> {
    this.tasks.push(args.length ? args[0] : (undefined! as T));

    if (!this.batchPromise) {
      this.batchPromise = (
        this.timeBeforeStart
          ? new Promise<void>(resolve =>
              setTimeout(resolve, this.timeBeforeStart),
            )
          : Promise.resolve()
      ).then(() => {
        let tasks = this.tasks;

        this.tasks = [];
        this.batchPromise = undefined;

        return this.handler(tasks);
      });
    }

    return this.batchPromise;
  }
}
